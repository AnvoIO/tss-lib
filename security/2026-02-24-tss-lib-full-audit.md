# Security Audit Report: bnb-chain/tss-lib

| Field | Value |
|-------|-------|
| **Repository** | `bnb-chain/tss-lib` (v2) |
| **Audit Date** | 2026-02-24 |
| **Commit** | `dd6f9f0` (branch: `security-review`) |
| **Scope** | Full codebase — ECDSA/EdDSA threshold signature scheme (keygen, signing, resharing) and supporting cryptographic primitives |
| **Prior Audit** | [Kudelski Security, 2019](https://github.com/bnb-chain/tss-lib/blob/master/audit/) |
| **Audit and Fixes By** | Robert Capps - Stratovera LLC \<robert@stratovera.io\> |

---

## Executive Summary

This audit was performed by Stratovera LLC. It reviewed the bnb-chain/tss-lib threshold signature library, which implements GG18/GG20 ECDSA and EdDSA multi-party computation protocols. The review identified **13 findings** across the cryptographic protocol implementation, error handling, and memory safety domains. Two critical issues involve unchecked nil returns from modular inverse operations and the ability to disable zero-knowledge security proofs via public API flags. Three high-severity issues affect hash function error propagation, timing side-channel resistance, and secret memory clearing. The codebase demonstrates strong fundamentals — proper CSPRNG usage, domain-separated hashing, and signature malleability protection — but requires targeted hardening in error propagation and defensive programming patterns.

### Finding Summary

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 2 | C1, C2 |
| **High** | 3 | H1, H2, H3 |
| **Medium** | 5 | M1, M2, M3, M4, M5 |
| **Low** | 3 | L1, L2, L3 |

### Top 3 Priority Recommendations

1. **Add nil-checks after every `ModInverse` call** (C1) — a nil result fed into arithmetic silently corrupts key shares and signatures.
2. **Remove or gate `NoProofMod`/`NoProofFac` behind build tags** (C2) — these flags disable Paillier ZK proofs, reducing security to the level of a semi-honest adversary.
3. **Propagate hash errors as `error` return values** (H1) — silent nil returns from `SHA512_256i` can cascade into nil-pointer panics or weak protocol outputs.

---

## Findings

### C1: Unchecked `ModInverse` Nil Returns

| | |
|---|---|
| **Severity** | 🔴 Critical |
| **Category** | Error Handling / Cryptographic Correctness |

**Description:** Go's `big.Int.ModInverse` returns `nil` when the input is not invertible modulo the given modulus. The tss-lib codebase calls `ModInverse` in 10+ locations without checking for nil. A nil result silently propagates through subsequent arithmetic, corrupting Lagrange interpolation coefficients, Paillier decryption, and signature shares.

**Affected Files:**

| Location | Context |
|----------|---------|
| `ecdsa/signing/round_4.go:43` | Theta inverse for signature reconstruction |
| `ecdsa/signing/prepare.go:43` | Lagrange coefficient in `PrepareForSigning` |
| `ecdsa/signing/prepare.go:61` | Lagrange coefficient (inner loop) |
| `eddsa/signing/prepare.go:39` | EdDSA Lagrange coefficient |
| `crypto/vss/feldman_vss.go:136` | Feldman VSS secret reconstruction |
| `crypto/paillier/paillier.go:188` | Paillier decryption |
| `crypto/paillier/paillier.go:204` | Paillier proof generation |
| `crypto/modproof/proof.go:53` | Mod proof construction |
| `ecdsa/keygen/prepare.go:141` | PreParams generation (beta) |

**Vulnerable Pattern:**

```go
// ecdsa/signing/round_4.go:42-43
// compute the multiplicative inverse thelta mod q
thetaInverse = modN.ModInverse(thetaInverse)
// thetaInverse may be nil — used directly at line 50 and 61
```

```go
// crypto/vss/feldman_vss.go:135-138
sub := modN.Sub(xs[j], share.ID)
subInv := modN.ModInverse(sub)       // nil if sub ≡ 0 (mod N)
div := modN.Mul(xs[j], subInv)       // nil propagates silently
times = modN.Mul(times, div)
```

```go
// crypto/paillier/paillier.go:187-189
inv := new(big.Int).ModInverse(Lg, privateKey.N)
m = common.ModInt(privateKey.N).Mul(Lc, inv) // nil inv → corrupted plaintext
```

**Impact:** A nil `ModInverse` result fed into multiplication produces a nil `*big.Int`, which when used in subsequent `Exp`, `Mul`, or `ScalarMult` calls will either panic or silently produce incorrect values. In signing, this corrupts the final signature. In VSS reconstruction, this corrupts the reconstructed secret. In Paillier decryption, this corrupts the plaintext message. An adversary who can influence inputs to produce a non-invertible value could exploit this to extract key shares.

**Recommended Fix:**

```go
// Wrap every ModInverse call with a nil check and return an error:
thetaInverse = modN.ModInverse(thetaInverse)
if thetaInverse == nil {
    return round.WrapError(errors.New("ModInverse: theta is not invertible"))
}
```

---

### C2: `NoProofMod`/`NoProofFac` Flags Disable Security Proofs

| | |
|---|---|
| **Severity** | 🔴 Critical |
| **Category** | Protocol Security / API Misuse |

**Description:** The `Parameters` struct exposes `SetNoProofMod()` and `SetNoProofFac()` methods that disable generation and verification of Paillier modulus and factorization zero-knowledge proofs. These proofs are essential for security against malicious adversaries. When disabled, stub proof objects with zero values are sent in their place, and verification is skipped with a warning log.

**Affected Files:**

| Location | Context |
|----------|---------|
| `tss/params.go:29-30` | Flag definitions |
| `tss/params.go:107-113` | Public setter methods |
| `ecdsa/keygen/round_2.go:141` | Skips ModProof generation |
| `ecdsa/keygen/round_3.go:87` | Skips ModProof verification |
| `ecdsa/keygen/round_2.go:121` | Skips FacProof generation |
| `ecdsa/keygen/round_3.go:112` | Skips FacProof verification |
| `ecdsa/resharing/round_2_new_step_1.go:95` | Skips ModProof in resharing |
| `ecdsa/resharing/round_4_new_step_2.go:81` | Skips ModProof verification in resharing |

**Vulnerable Pattern:**

```go
// tss/params.go:107-113
func (params *Parameters) SetNoProofMod() {
    params.noProofMod = true
}

func (params *Parameters) SetNoProofFac() {
    params.noProofFac = true
}
```

```go
// ecdsa/keygen/round_2.go:140-144
modProof := &modproof.ProofMod{W: zero, X: *new([80]*big.Int), ...} // stub
if !round.Parameters.NoProofMod() {
    modProof, err = modproof.NewProof(ContextI, round.save.PaillierSK.N,
        round.save.PaillierSK.P, round.save.PaillierSK.Q, round.Rand())
```

```go
// ecdsa/keygen/round_3.go:87-90
modProof, err := r2msg2.UnmarshalModProof()
if err != nil && round.Parameters.NoProofMod() {
    // For old parties, the modProof could be not exist
    common.Logger.Warningf("modProof not exist:%s", Ps[j])
```

**Impact:** Without ModProof validation, a malicious party can use a Paillier modulus N that is not the product of two safe primes, breaking the security assumptions of the Paillier cryptosystem and enabling extraction of other parties' key shares. Without FacProof validation, a malicious party can use a Paillier modulus whose factorization is known to have small factors, enabling decryption of encrypted values. These flags reduce the protocol from malicious security to semi-honest security.

**Recommended Fix:**

```go
// Option A: Remove the public API entirely and use build tags for testing
// +build testing

func (params *Parameters) SetNoProofMod() { params.noProofMod = true }
func (params *Parameters) SetNoProofFac() { params.noProofFac = true }

// Option B: Log a prominent warning and require explicit opt-in
func (params *Parameters) SetNoProofMod() {
    Logger.Warn("SECURITY DEGRADED: Paillier modulus proofs disabled. " +
        "DO NOT use in production with untrusted parties.")
    params.noProofMod = true
}
```

---

### H1: Hash Function Errors Return Nil Without Propagation

| | |
|---|---|
| **Severity** | 🟠 High |
| **Category** | Error Handling |

**Description:** The core hash functions `SHA512_256`, `SHA512_256i`, and `SHA512_256i_TAGGED` log errors from `state.Write()` but return `nil` instead of propagating errors. Callers have no way to distinguish between "empty input" (also nil) and "hash computation failed." A nil hash value silently flowing into ZK proof construction or Fiat-Shamir challenges would critically weaken protocol security.

**Affected Files:**

| Location | Context |
|----------|---------|
| `common/hash.go:51-53` | `SHA512_256` returns nil on Write error |
| `common/hash.go:89-91` | `SHA512_256i` returns nil on Write error |
| `common/hash.go:135-137` | `SHA512_256i_TAGGED` returns nil on Write error |

**Vulnerable Pattern:**

```go
// common/hash.go:89-91
if _, err := state.Write(data); err != nil {
    Logger.Errorf("SHA512_256i Write() failed: %v", err)
    return nil  // caller receives nil with no error indication
}
```

**Impact:** While Go's hash.Hash.Write() is documented to never return an error in practice, defensive code should not rely on this. If a nil hash is returned and used as a Fiat-Shamir challenge in a ZK proof, the proof becomes trivially forgeable. If used in commitment schemes, it enables commitment equivocation.

**Recommended Fix:**

Change function signatures to return `(*big.Int, error)`:

```go
func SHA512_256i(in ...*big.Int) (*big.Int, error) {
    // ...
    if _, err := state.Write(data); err != nil {
        return nil, fmt.Errorf("SHA512_256i: hash write failed: %w", err)
    }
    return new(big.Int).SetBytes(state.Sum(nil)), nil
}
```

Note: This is a breaking API change. A phased approach could first add `SHA512_256iE` variants that return errors, migrate callers, then deprecate the old signatures.

---

### H2: No Constant-Time Operations for Secret Comparisons

| | |
|---|---|
| **Severity** | 🟠 High |
| **Category** | Side-Channel Resistance |
| **Prior Art** | KS-BTL-O-12, KS-BTL-O-13 (Kudelski 2019 — noted but not required to fix) |

**Description:** The codebase uses `bytes.Equal()` and `big.Int.Cmp()` for comparing values derived from secret material. These operations are not constant-time and may leak information through timing side channels. While exploitation requires local access or precise network timing measurements, this is a defense-in-depth concern for a cryptographic library.

**Affected Files:**

| Location | Context |
|----------|---------|
| `crypto/ckd/child_key_derivation.go:93` | Key derivation checksum comparison |
| `ecdsa/resharing/round_2_new_step_1.go:49` | SSID validation in resharing |

**Vulnerable Pattern:**

```go
// crypto/ckd/child_key_derivation.go:91-94
checkSum := decoded[len(decoded)-4:]
expectedCheckSum := doubleHashB(payload)[:4]
if !bytes.Equal(checkSum, expectedCheckSum) {  // timing leak
    return nil, errors.New("invalid extended key")
}
```

**Impact:** Timing differences in comparison operations can reveal information about secret values byte-by-byte. For key derivation checksums, this could help an attacker validate guesses about extended key data. The practical exploitability depends on the attacker's ability to measure timing with sufficient precision.

**Recommended Fix:**

```go
import "crypto/subtle"

if subtle.ConstantTimeCompare(checkSum, expectedCheckSum) != 1 {
    return nil, errors.New("invalid extended key")
}
```

---

### H3: Incomplete Secret Memory Clearing

| | |
|---|---|
| **Severity** | 🟠 High |
| **Category** | Memory Safety |

**Description:** The codebase demonstrates awareness of secret clearing (setting local variables to `zero` after use), but the clearing is incomplete. In multiple locations, a local variable is cleared while the same value persists in a `temp` struct field. Additionally, several sensitive values created during signing are never cleared at all.

**Affected Files:**

| Location | Context |
|----------|---------|
| `ecdsa/keygen/round_1.go:45,56` | `ui` cleared locally but persists in `round.temp.ui` |
| `eddsa/keygen/round_1.go:49,60` | Same pattern in EdDSA keygen |
| `ecdsa/signing/round_5.go:66-94` | `si`, `li`, `roI` stored in temp, never cleared |
| `ecdsa/signing/round_5.go:69-70` | `w` and `k` cleared, but `sigma`, `gamma`, `m` are not |

**Vulnerable Pattern:**

```go
// ecdsa/keygen/round_1.go:43-57
ui := common.GetRandomPositiveInt(round.PartialKeyRand(), round.EC().Params().N)

round.temp.ui = ui  // secret persists here

// security: the original u_i may be discarded
ui = zero // clears local variable only
_ = ui    // silences a linter warning
// round.temp.ui still holds the secret key share
```

```go
// ecdsa/signing/round_5.go:66-94
si := modN.Add(modN.Mul(round.temp.m, round.temp.k), modN.Mul(rx, round.temp.sigma))

round.temp.w = zero  // cleared ✓
round.temp.k = zero  // cleared ✓

li := common.GetRandomPositiveInt(round.Rand(), N)
roI := common.GetRandomPositiveInt(round.Rand(), N)
// ...
round.temp.li = li     // never cleared ✗
round.temp.roi = roI   // never cleared ✗
round.temp.si = si     // never cleared ✗
```

**Impact:** Sensitive cryptographic material (partial key shares, signature nonces, ephemeral secrets) remains in process memory after protocol completion. This material is vulnerable to extraction via memory dumps, core dumps, swap files, or cold-boot attacks. In Go, the garbage collector may also copy these values to new memory locations, leaving additional copies.

**Recommended Fix:**

Add a `Clear()` method to temp structs that zeros all sensitive fields, and call it at protocol completion:

```go
func (t *localTempData) Clear() {
    if t.ui != nil { t.ui.SetInt64(0) }
    if t.si != nil { t.si.SetInt64(0) }
    if t.li != nil { t.li.SetInt64(0) }
    if t.roi != nil { t.roi.SetInt64(0) }
    if t.sigma != nil { t.sigma.SetInt64(0) }
    if t.gamma != nil { t.gamma.SetInt64(0) }
    // ... all sensitive fields
}
```

Note: Go does not guarantee that the GC won't have already copied the old value. For highest assurance, consider using `memguard` or similar libraries that pin memory pages.

---

### M1: Panic-Based Validation in Protocol-Critical Paths

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Category** | Robustness / Denial of Service |
| **Prior Art** | KS-BTL-F-08 (Kudelski 2019 — partially fixed with validation, panics remained) |

**Description:** The `PrepareForSigning` function and `GeneratePreParams` use `panic()` for input validation instead of returning errors. In a long-running service, an unexpected panic crashes the entire process rather than allowing graceful error handling and recovery.

**Affected Files:**

| Location | Context |
|----------|---------|
| `ecdsa/signing/prepare.go:22` | `len(ks) != len(bigXs)` |
| `ecdsa/signing/prepare.go:25` | `len(ks) != pax` |
| `ecdsa/signing/prepare.go:28` | `len(ks) <= i` |
| `ecdsa/signing/prepare.go:40` | Duplicate party index |
| `ecdsa/signing/prepare.go:58` | Duplicate party index (inner loop) |
| `ecdsa/keygen/prepare.go:59` | Invalid `optionalConcurrency` arg count |
| `eddsa/signing/prepare.go:35,39` | Same pattern in EdDSA |

**Vulnerable Pattern:**

```go
// ecdsa/signing/prepare.go:19-29
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int,
    bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
    if len(ks) != len(bigXs) {
        panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)",
            len(ks), len(bigXs)))
    }
    // ...
    if ksj.Cmp(ksi) == 0 {
        panic(fmt.Errorf("index of two parties are equal"))
    }
```

**Impact:** A malicious or buggy peer providing duplicate party indices or mismatched arrays will crash the hosting process. In production deployments (validators, custody services), this constitutes a denial-of-service vector.

**Recommended Fix:**

Change `PrepareForSigning` to return `error`:

```go
func PrepareForSigning(...) (wi *big.Int, bigWs []*crypto.ECPoint, err error) {
    if len(ks) != len(bigXs) {
        return nil, nil, fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs)")
    }
    // ...
}
```

---

### M2: `SHA512_256i_TAGGED` Skips Error Check on Initial Writes

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Category** | Error Handling |

**Description:** In `SHA512_256i_TAGGED`, the two initial `state.Write(tagBz)` calls (which write the tag prefix for domain separation) do not check the returned error, unlike the final `state.Write(data)` call on line 135 which does check.

**Affected Files:**

| Location | Context |
|----------|---------|
| `common/hash.go:101` | First `state.Write(tagBz)` — no error check |
| `common/hash.go:102` | Second `state.Write(tagBz)` — no error check |

**Vulnerable Pattern:**

```go
// common/hash.go:100-102
state := crypto.SHA512_256.New()
state.Write(tagBz)   // error ignored
state.Write(tagBz)   // error ignored
```

Compare with the checked write on line 135:
```go
if _, err := state.Write(data); err != nil {
    Logger.Error(err)
    return nil
}
```

**Impact:** If the tag write fails silently, the hash loses its domain separation prefix, potentially enabling cross-protocol hash collisions. While `hash.Hash.Write` is specified to never fail in Go's standard library, consistency in error handling is important for a cryptographic library.

**Recommended Fix:**

```go
if _, err := state.Write(tagBz); err != nil {
    return nil // or return error per H1 recommendation
}
if _, err := state.Write(tagBz); err != nil {
    return nil
}
```

---

### M3: `GetRandomPositiveInt` Nil Return Unchecked in Callers

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Category** | Error Handling / Defensive Programming |
| **Prior Art** | KS-BTL-F-05 (Kudelski 2019 — fixed the infinite loop, but callers still unchecked) |

**Description:** `GetRandomPositiveInt` returns nil when `lessThan` is nil or non-positive. Multiple callers use the return value directly without nil checks, which would cause nil-pointer panics in subsequent operations.

**Affected Files:**

| Location | Context |
|----------|---------|
| `common/random.go:39-41` | Function returns nil on invalid input |
| `ecdsa/signing/round_1.go:54-55` | `k` and `gamma` unchecked |
| `ecdsa/signing/round_5.go:72-73` | `li` and `roI` unchecked |
| `ecdsa/keygen/round_1.go:43` | `ui` unchecked |
| `eddsa/keygen/round_1.go:48` | `ui` unchecked |
| `eddsa/signing/round_1.go:44` | `ri` unchecked |
| `crypto/dlnproof/proof.go:40` | `a[i]` unchecked in loop |
| `common/random.go:109` | `GetRandomQuadraticNonResidue` passes result to `big.Jacobi` without check |

**Vulnerable Pattern:**

```go
// common/random.go:39-41
func GetRandomPositiveInt(rand io.Reader, lessThan *big.Int) *big.Int {
    if lessThan == nil || zero.Cmp(lessThan) != -1 {
        return nil
    }
    // ...
}

// ecdsa/signing/round_1.go:54-55
k := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
gamma := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
// k, gamma used directly — nil would panic at ScalarBaseMult
```

```go
// common/random.go:107-113 (transitive)
func GetRandomQuadraticNonResidue(rand io.Reader, n *big.Int) *big.Int {
    for {
        w := GetRandomPositiveInt(rand, n) // nil if n is invalid
        if big.Jacobi(w, n) == -1 {       // panic on nil w
            return w
        }
    }
}
```

**Impact:** While `EC().Params().N` should always be valid for standard curves, a nil return would cause a nil-pointer panic, crashing the process. The transitive path through `GetRandomQuadraticNonResidue` → `GetRandomPositiveInt` is particularly dangerous as it's used in `modproof.NewProof`.

**Recommended Fix:**

Either change `GetRandomPositiveInt` to panic on invalid inputs (fail-fast), or add nil checks at all call sites:

```go
k := common.GetRandomPositiveInt(round.Rand(), round.EC().Params().N)
if k == nil {
    return round.WrapError(errors.New("failed to generate random k"))
}
```

---

### M4: Incomplete TODO Items in Security-Critical Code

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Category** | Code Completeness |

**Description:** A TODO comment in the ModProof verification function indicates that a basic properties checker was planned but never implemented. This is in a security-critical verification path that validates zero-knowledge proofs for Paillier modulus correctness.

**Affected Files:**

| Location | Context |
|----------|---------|
| `crypto/modproof/proof.go:118` | Missing basic properties checker in `Verify()` |

**Vulnerable Pattern:**

```go
// crypto/modproof/proof.go:114-121
func (pf *ProofMod) Verify(Session []byte, N *big.Int) bool {
    if pf == nil || !pf.ValidateBasic() {
        return false
    }
    // TODO: add basic properties checker
    if isQuadraticResidue(pf.W, N) {
        return false
    }
```

**Impact:** Without a properties checker, the verification may accept proofs with malformed parameters that pass the quadratic residue check but violate other invariants. The specific properties that should be checked (e.g., N > minimum bit length, N is odd, proof elements are in the correct range) are not validated.

**Recommended Fix:**

Implement the properties checker:

```go
// Add before the quadratic residue check:
if N.BitLen() < 2048 {
    return false
}
if N.Bit(0) == 0 { // N must be odd
    return false
}
// Verify all proof elements are in range [1, N)
for _, x := range pf.X {
    if x == nil || x.Sign() <= 0 || x.Cmp(N) >= 0 {
        return false
    }
}
```

---

### M5: `padToLengthBytesInPlace` Potential Memory Leak of Signature Data

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Category** | Memory Safety / Performance |

**Description:** The `padToLengthBytesInPlace` function pads a byte slice by repeatedly prepending a zero byte in a loop, creating a new allocation on every iteration. This is O(n²) in the padding length and leaves intermediate copies of signature data (R, S values) scattered across the heap.

**Affected Files:**

| Location | Context |
|----------|---------|
| `ecdsa/signing/finalize.go:102-109` | Function definition |
| `ecdsa/signing/finalize.go:60-61` | Called with signature R and S values |

**Vulnerable Pattern:**

```go
// ecdsa/signing/finalize.go:102-109
func padToLengthBytesInPlace(src []byte, length int) []byte {
    oriLen := len(src)
    if oriLen < length {
        for i := 0; i < length-oriLen; i++ {
            src = append([]byte{0}, src...) // new allocation each iteration
        }
    }
    return src
}
```

Called with sensitive values:
```go
// ecdsa/signing/finalize.go:60-61
round.data.R = padToLengthBytesInPlace(round.temp.rx.Bytes(), bitSizeInBytes)
round.data.S = padToLengthBytesInPlace(sumS.Bytes(), bitSizeInBytes)
```

**Impact:** Each iteration allocates a new byte slice containing the signature component. Previous copies are not zeroed and remain in memory until garbage collected. For a 32-byte value needing 1 byte of padding, this creates 1 leaked copy. The copies contain partial signature data that could be recovered from memory.

**Recommended Fix:**

```go
func padToLengthBytesInPlace(src []byte, length int) []byte {
    if len(src) >= length {
        return src
    }
    padded := make([]byte, length)
    copy(padded[length-len(src):], src)
    // Zero the original
    for i := range src {
        src[i] = 0
    }
    return padded
}
```

---

### L1: Signature Malleability Normalization (Positive Observation)

| | |
|---|---|
| **Severity** | 🟢 Low (Informational — Correctly Implemented) |
| **Category** | Signature Security |

**Description:** The finalization round correctly normalizes the ECDSA signature S value to the lower half of the curve order, preventing signature malleability attacks. This is a positive finding.

**Affected Files:**

| Location | Context |
|----------|---------|
| `ecdsa/signing/finalize.go:52-56` | S-value normalization |

**Implementation:**

```go
// ecdsa/signing/finalize.go:52-56
secp256k1halfN := new(big.Int).Rsh(round.Params().EC().Params().N, 1)
if sumS.Cmp(secp256k1halfN) > 0 {
    sumS.Sub(round.Params().EC().Params().N, sumS)
    recid ^= 1
}
```

**Assessment:** This follows Bitcoin's BIP-62 and Ethereum's EIP-2 requirements. The recovery ID is correctly flipped when S is negated. The final signature is also verified against the public key at `finalize.go:78` before output, providing an additional safety net.

---

### L2: Hardcoded Cryptographic Parameters (Acceptable)

| | |
|---|---|
| **Severity** | 🟢 Low (Informational) |
| **Category** | Configuration |

**Description:** Security parameters are hardcoded as constants throughout the codebase. While this prevents runtime configuration, the chosen values are appropriate for the security level targeted.

**Affected Files:**

| Location | Parameter | Value |
|----------|-----------|-------|
| `ecdsa/keygen/prepare.go:25` | Paillier modulus length | 2048 bits |
| `ecdsa/keygen/prepare.go:27` | Safe prime bit length | 1024 bits |
| `crypto/dlnproof/proof.go:23` | DLN proof iterations | 128 |
| `crypto/modproof/proof.go:18` | Mod proof iterations | 80 |

**Assessment:** The Paillier modulus of 2048 bits provides ~112-bit security, consistent with the ECDSA curves used (secp256k1, P-256). The proof iteration counts provide adequate soundness (2^-128 and 2^-80 respectively). However, these parameters cannot be upgraded without code changes. Consider making them configurable for future-proofing, or documenting the security level they provide.

---

### L3: No Threshold Parameter Validation

| | |
|---|---|
| **Severity** | 🟢 Low |
| **Category** | API Safety |

**Description:** The `NewParameters` and `NewReSharingParameters` constructors accept threshold and party count values without validation. Invalid configurations (e.g., threshold ≥ partyCount, threshold = 0, negative values) are silently accepted and will cause failures or undefined behavior later in the protocol.

**Affected Files:**

| Location | Context |
|----------|---------|
| `tss/params.go:48-60` | `NewParameters` — no validation |
| `tss/params.go:134-142` | `NewReSharingParameters` — no validation |

**Vulnerable Pattern:**

```go
// tss/params.go:48-60
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID,
    partyCount, threshold int) *Parameters {
    return &Parameters{
        ec:         ec,
        partyCount: partyCount,
        threshold:  threshold,  // no validation: could be 0, negative, or >= partyCount
        // ...
    }
}
```

**Impact:** Invalid threshold parameters will cause subtle failures during keygen or signing (e.g., VSS share creation with threshold 0, or signing with more parties than shares). These failures manifest as panics or incorrect outputs rather than clear validation errors.

**Recommended Fix:**

```go
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID,
    partyCount, threshold int) (*Parameters, error) {
    if threshold <= 0 {
        return nil, fmt.Errorf("threshold must be positive, got %d", threshold)
    }
    if partyCount <= 0 {
        return nil, fmt.Errorf("partyCount must be positive, got %d", partyCount)
    }
    if threshold >= partyCount {
        return nil, fmt.Errorf("threshold (%d) must be less than partyCount (%d)",
            threshold, partyCount)
    }
    // ...
}
```

---

## Positive Observations

The following aspects of the codebase reflect strong security practices:

1. **CSPRNG Usage:** All random number generation uses `crypto/rand.Reader` via the configurable `Rand()` interface, with no use of `math/rand`. The `MustGetRandomInt` function correctly panics on entropy failures rather than falling back to weak randomness.

2. **Domain-Separated Hashing:** The `SHA512_256i_TAGGED` function implements proper tagged hashing with double tag prefix, preventing cross-protocol hash collisions. Length prefixes and delimiters in `SHA512_256i` prevent length-extension and concatenation attacks.

3. **SHA-512/256 Choice:** Using SHA-512/256 (truncated SHA-512) provides resistance to length-extension attacks and better performance on 64-bit architectures compared to SHA-256.

4. **Signature Verification:** The final ECDSA signature is verified against the public key before output (`finalize.go:78`), catching any computation errors before they reach the caller.

5. **S-Value Normalization:** Correct BIP-62/EIP-2 signature malleability protection (see L1).

6. **Paillier ZK Proofs:** When enabled, the library implements ModProof and FacProof for Paillier key validation, providing malicious-adversary security per the GG20 specification.

7. **Commitment Scheme:** Hash-based commitments with proper randomness are used throughout the protocol to prevent premature information disclosure.

---

## Recommendations Summary

| Priority | Action | Findings |
|----------|--------|----------|
| **P0 — Immediate** | Add nil checks after all `ModInverse` calls; return errors instead of nil | C1 |
| **P0 — Immediate** | Restrict `NoProofMod`/`NoProofFac` to test builds or add prominent warnings | C2 |
| **P1 — High** | Change hash functions to return `(*big.Int, error)` and propagate errors | H1, M2 |
| **P1 — High** | Use `crypto/subtle.ConstantTimeCompare` for all secret-derived comparisons | H2 |
| **P1 — High** | Implement comprehensive `Clear()` methods on all temp structs | H3, M5 |
| **P2 — Medium** | Replace `panic()` with error returns in `PrepareForSigning` and `GeneratePreParams` | M1 |
| **P2 — Medium** | Add nil checks for all `GetRandomPositiveInt` callers | M3 |
| **P2 — Medium** | Implement the ModProof properties checker | M4 |
| **P3 — Low** | Add parameter validation to `NewParameters` and `NewReSharingParameters` | L3 |
| **P3 — Low** | Consider making security parameters configurable for future upgrades | L2 |

---

## Cross-Reference: Kudelski Security Audit (2019-10-04)

The original [Kudelski Security audit](https://github.com/bnb-chain/tss-lib/releases/download/v1.0.0/audit-binance-tss-lib-final-20191018.pdf) (commit `31c67c55`) identified 10 findings and 20 observations. All were reported as fixed at the time. This section documents which 2019 findings overlap with the current audit and their present status.

### Findings Still Fully Remediated

| 2019 Finding | Description | Current Status |
|-------------|-------------|----------------|
| KS-BTL-F-01 | Message not validated in Zq | **Fixed** — `ecdsa/signing/round_1.go:40` checks `m < N` |
| KS-BTL-F-02 | Missing `u` in ZK proof hash (MtAwc) | **Fixed** — `crypto/mta/proofs.go:109,283` includes `u.X(), u.Y()` |
| KS-BTL-F-03 | Not using safe primes for NTilde | **Fixed** — `common/safe_prime.go` implements Sophie Germain generation |
| KS-BTL-F-04 | `MustGetRandomInt` panics on bad bits | **Fixed** — `common/random.go:24` validates `0 < bits <= 5000` |
| KS-BTL-F-05 | `GetRandomPositiveInt` infinite loop | **Fixed** — `common/random.go:40` guards `lessThan <= 0` |
| KS-BTL-F-06 | `GetRandomPositiveRelativelyPrimeInt` infinite loop | **Fixed** — `common/random.go:74` same guard pattern |
| KS-BTL-F-07 | No final signature verification | **Fixed** — `ecdsa/signing/finalize.go:72-81` calls `ecdsa.Verify()` |
| KS-BTL-F-09 | SHA512_256 hash collision via `$` separator | **Fixed** — `common/hash.go` uses length-prefixed encoding |
| KS-BTL-F-10 | Unhandled errors in MtA | **Fixed** — `crypto/mta/share_protocol.go` checks all returns |
| KS-BTL-O-01 | `NewECPoint` no on-curve validation | **Fixed** — `crypto/ecpoint.go:42` validates in constructor |

### Findings That Overlap With This Audit

| 2019 Finding | This Audit | Overlap |
|-------------|-----------|---------|
| KS-BTL-F-08: `PrepareForSigning` panics | **M1** | The 2019 fix added input validation but kept `panic()`. M1 identified remaining panics (duplicate index checks) and recommended returning `error` instead. Now fully fixed. |
| KS-BTL-O-12: `big.Int` not constant-time | **H2** | The 2019 audit noted `big.Int.Exp` timing leaks as informational. H2 extends this to `big.Int.Cmp` and `bytes.Equal` on secret-derived values. The `crypto/ckd` and resharing SSID comparisons have been fixed with `subtle.ConstantTimeCompare`. |
| KS-BTL-O-13: Non-constant-time commitment verification | **H2** | The 2019 audit flagged `hash.Cmp(C)` in `crypto/commitments/commitment.go:62` as a timing concern. This was **not fixed** at the time (marked "does not necessarily need to be fixed"). Now fixed with `subtle.ConstantTimeCompare`. |
| KS-BTL-F-05: `GetRandomPositiveInt` nil return | **M3** | The 2019 fix added early `return nil` for invalid inputs, but M3 identified that callers never check for nil returns, creating a downstream panic risk. |

---

## Appendix A: February 25-26, 2026 Follow-up Findings and Remediation

This appendix incorporates and supersedes the detailed content that was previously maintained in standalone follow-up and consolidated reports.

These findings were discovered after the main February 24, 2026 report publication and are treated as part of the same February 2026 audit cycle.

### A.1 Metadata

| Field | Value |
|---|---|
| Repository | `bnb-chain/tss-lib` |
| Follow-up Review Dates | `2026-02-25`, `2026-02-26` |
| Base | `main` (`dd6f9f0`) |
| Reviewed Branch (pre-squash) | `security-review` (`690f45a`) |
| Intermediate Checkpoint (pre-squash) | `1c65ae6` (clean-worktree checkpoint before final closure patch set) |
| Canonical Merge Reference | `https://github.com/AnvoIO/tss-lib` |
| Post-Merge Canonical Commit | `e230d0c` (canonical commit on `main`) |
| Inputs | MR 1 diff + this full audit report + independent secondary review + final closure patch set |
| **Audit and Fixes By** | Robert Capps - Stratovera LLC \<robert@stratovera.io\> |

### A.2 Executive Summary

The follow-up and secondary reviews identified nine additional issues beyond the 13 findings in the main body (`C1..L3`).
All nine additional issues (`F1..F6`, `S1..S3`) are remediated in the current patched branch with targeted regression coverage.
`F1..F4` were identified on 2026-02-25; `F5..F6` were identified on 2026-02-26 during a secondary review; `S1..S3` were finalized on 2026-02-26 during reconciliation of supplemental findings against code.
Commit hashes referenced in this appendix are pre-squash branch context and should be interpreted together with MR `!1`; after squash merge, the canonical immutable code reference is the squash commit on `main`.

### A.3 Follow-up Findings (`F1..F6`, `S1..S3`)

| ID | Severity | Finding | Exploit Summary (pre-fix) | Final Status |
|---|---|---|---|---|
| F1 | Critical | Production-accessible `SetNoProofMod/SetNoProofFac` downgrade path | Malicious participant could exploit proof-disabled deployments to bypass Paillier proof enforcement and weaken malicious-security guarantees | Fixed (secure-by-default gating via build tags) |
| F2 | High | CKD malformed extended key accepted, later panic path | Crafted xpub-like input could pass parse and trigger nil dereference in serialization/logging | Fixed |
| F3 | Medium | Panic-based DoS in selected public/common paths | Malformed input/state could crash long-running signing/key-management services | Fixed (scoped to identified paths) |
| F4 | Low/Medium | Concurrency validation mismatch panic | Invalid concurrency configuration could trigger runtime panic in verifier initialization | Fixed |
| F5 | Medium | Missing negative sign-bit validation on message hash input | Negative `*big.Int` message hash bypasses bounds check; `.Bytes()` silently drops sign, mutating the signed message | Fixed |
| F6 | Medium | `SHA512_256i` nil-pointer panic on nil `*big.Int` input | Nil element in variadic `*big.Int` args causes nil-pointer dereference at `.Bytes()` call | Fixed |
| S1 | Medium | Residual M5 path in exported `common.PadToLengthBytesInPlace` | Loop-prepend implementation remained in shared utility, preserving O(n²) allocation behavior and leaving extra byte copies in heap | Fixed |
| S2 | Low/Operational | Resharing verification accountability TODOs | Selected resharing validation paths returned on first failure and did not aggregate all malicious culprits | Fixed |
| S3 | Low | Missing `newCtx` nil validation in `NewReSharingParameters` | Nil `newCtx` could be accepted and fail later in protocol execution instead of fail-fast constructor validation | Fixed |

### A.4 Exploitation Summary (Pre-Fix Behavior)

| ID | How it could be exploited | Impact |
|---|---|---|
| F1 | Operator/test harness calls `SetNoProofMod()` / `SetNoProofFac()`, or compatibility code leaves them enabled; malicious participant omits/corrupts Paillier proofs and still progresses | Downgrade from malicious security assumptions; acceptance of unproven Paillier parameters |
| F2 | Untrusted xpub-like input crafted to pass checksum/length but decode to nil curve point; later call to `String()` crashes | Remote-triggerable crash in services that parse then serialize/log extended keys |
| F3 | Malformed state or bad caller args reach panic-based code paths in key setup / serialization helpers | Process crash (DoS) in long-running services |
| F4 | Misconfiguration sets `concurrency=0`; downstream verifier constructor panics | Startup/runtime crash due to configuration footgun |
| F5 | Caller provides a negative `*big.Int` as the message hash `m`; the existing `m >= N` check passes because `Cmp` treats negative values as less than positive values; subsequent `.Bytes()` call drops the sign bit, silently computing a signature over `\|m\|` instead of `m` | Signature computed over wrong message value; signature verification failures that are difficult to diagnose; undefined behavior in custom protocol wrappers that rely on sign preservation |
| F6 | A nil `*big.Int` element is passed in the variadic args to `SHA512_256i`; the function dereferences it directly with `.Bytes()` without a nil guard, unlike its sibling `SHA512_256i_TAGGED` which does check | Nil-pointer panic / process crash (DoS); exploitable by any code path that constructs hash inputs from potentially-nil protocol values |
| S1 | Code paths using exported `common.PadToLengthBytesInPlace` would still trigger repeated allocations and retain intermediate copies of sensitive byte data | Memory-copy amplification and residual sensitive byte retention risk |
| S2 | Multiple old-committee malicious senders during resharing validation would not all be surfaced in one error path | Reduced operator visibility and weaker malicious-participant accountability |
| S3 | Misconfigured integrator passes nil `newCtx`; constructor accepts and failure is deferred | Configuration footgun / delayed runtime error |

### A.5 Fix Matrix

| ID | Status | Fix Summary | Primary Files |
|---|---|---|---|
| F1 | **Fixed** | `SetNoProof*` moved behind build tags; secure build blocks proof-disable toggles | `tss/params.go`, `tss/params_noproof_secure.go`, `tss/params_noproof_insecure.go` |
| F2 | **Fixed** | Reject invalid points on parse; harden `String()` against invalid internal state | `crypto/ckd/child_key_derivation.go` |
| F3 | **Fixed (scoped to identified paths)** | Replace panic-on-invalid-input behavior with graceful handling / error returns in identified paths | `crypto/paillier/paillier.go`, `ecdsa/keygen/local_party.go`, `ecdsa/keygen/save_data.go`, `eddsa/keygen/save_data.go` |
| F4 | **Fixed** | Clamp invalid concurrency to minimum valid value | `tss/params.go`, `ecdsa/keygen/dln_verifier.go` |
| F5 | **Fixed** | Add `m.Sign() < 0` check to message hash validation in ECDSA; add equivalent negative-sign rejection in EdDSA | `ecdsa/signing/round_1.go`, `eddsa/signing/round_1.go` |
| F6 | **Fixed** | Add nil guard in `SHA512_256i` input loop, matching the existing pattern in `SHA512_256i_TAGGED` | `common/hash.go` |
| S1 | **Fixed** | Replace loop-prepend padding with single-allocation copy and zero original source bytes when padding | `common/slice.go`, `common/slice_test.go` |
| S2 | **Fixed** | Aggregate culprit collection in selected resharing validation loops and return all observed culprits | `ecdsa/resharing/round_4_new_step_2.go`, `eddsa/resharing/round_4_new_step_2.go`, `ecdsa/resharing/adversarial_test.go` |
| S3 | **Fixed** | Add fail-fast nil-check for `newCtx` in resharing parameter constructor | `tss/params.go`, `tss/params_test.go` |

### A.6 Detailed Remediation Notes

#### F1: Proof-bypass flags in production API

Pre-fix issue:
- Proof-disable methods were callable in all builds and could silently weaken protocol guarantees.

Implemented fix:
- Secure builds (`default`) now block proof-disable methods:
  - `SetNoProofMod()` and `SetNoProofFac()` log and do not enable flags.
- Insecure behavior is explicitly opt-in via build tag:
  - `-tags insecure_noproofs`

Security effect:
- Production/default builds fail closed on proof enforcement.
- Compatibility/testing downgrade path remains available only through explicit insecure build configuration.

#### F2: CKD malformed extended key acceptance and panic

Pre-fix issue:
- `NewExtendedKeyFromString` could return `(key, nil)` with `key.X/key.Y == nil` for malformed non-secp inputs.
- `(*ExtendedKey).String()` could dereference nil fields and panic.

Implemented fix:
- Reject invalid points after `elliptic.Unmarshal` (`X/Y` nil -> error).
- Harden `String()` with defensive checks on key fields; invalid state returns `""` instead of panic.

Security effect:
- Crafted malformed extended keys no longer survive parse into unsafe objects.
- Serialization/logging paths are hardened against nil-pointer crashes.

#### F3: Panic-based DoS paths in public/common call paths

Pre-fix issue (identified subset):
- Panic on invalid optional arg count in Paillier keygen.
- Panic-style behavior around optional preparams handling in keygen constructor paths.
- Panic on signer mismatch in save-data subset builders.

Implemented fix:
- `paillier.GenerateKeyPair`: returns explicit errors for invalid optional concurrency args.
- `ecdsa/keygen.NewLocalParty`: invalid optional preparams are ignored with error logging.
- `BuildLocalSaveDataSubset` (ECDSA/EdDSA): no panic on missing signer mapping; logs and returns source data.

Security effect:
- Invalid input/state no longer trivially crashes process in these paths.

#### F4: Concurrency validation mismatch

Pre-fix issue:
- `SetConcurrency` allowed invalid values; downstream verifier panicked on zero.

Implemented fix:
- `SetConcurrency` clamps values `< 1` to `1`.
- `NewDlnProofVerifier` clamps values `< 1` to `1`.

Security effect:
- Removes configuration-induced panic vector.

#### F5: Negative message hash sign-bit bypass

Pre-fix issue:
- `ecdsa/signing/round_1.go:40` checked `m.Cmp(N) >= 0` but not `m.Sign() < 0`. A negative `*big.Int` passes the upper-bound check because `Cmp` considers negative values less than positive values.
- `eddsa/signing/round_1.go` had no message hash validation at all.

Implemented fix:
- ECDSA: the bounds check now reads `m.Sign() < 0 || m.Cmp(N) >= 0`, rejecting negative values before they can propagate.
- EdDSA: a new `m.Sign() < 0` check is added at the top of `round1.Start()`, rejecting negative message hashes early.

Security effect:
- Negative `*big.Int` values are rejected with a clear error before any protocol computation occurs.
- Eliminates the silent sign-bit truncation that would cause signatures to be computed over `|m|` instead of `m`.

#### F6: `SHA512_256i` nil-pointer panic on nil input

Pre-fix issue:
- `SHA512_256i` (`common/hash.go:72`) iterates over input `*big.Int` values and calls `n.Bytes()` directly without a nil check.
- The sibling function `SHA512_256i_TAGGED` (`common/hash.go:118-122`) already contained a nil guard that substituted `zero.Bytes()` for nil inputs, making this an inconsistency.

Implemented fix:
- Added a nil check in the `SHA512_256i` input loop matching the `SHA512_256i_TAGGED` pattern: nil inputs are treated as zero-valued `*big.Int`.

Security effect:
- Eliminates nil-pointer panic path in a core hash utility used throughout the protocol.
- Ensures consistent nil-handling behavior across all `SHA512_256i*` variants.

#### S1: Residual exported padding utility path (`common.PadToLengthBytesInPlace`)

Pre-fix issue:
- The M5 remediation was applied in `ecdsa/signing/finalize.go`, but the exported helper `common.PadToLengthBytesInPlace` retained the prior loop-prepend implementation (`append([]byte{0}, src...)` per byte), preserving O(n²) behavior and intermediate heap copies.

Implemented fix:
- Replaced loop-prepend logic with single-allocation padding (`make` + `copy`) in `common/slice.go`.
- Added best-effort zeroization of the original `src` bytes when padding is applied.
- Added unit coverage in `common/slice_test.go` for:
  - padded output correctness,
  - no-op semantics when `len(src) >= length`,
  - source-byte zeroization,
  - nil-input handling.

Security effect:
- Removes repeated allocation/copy amplification in shared utility usage.
- Reduces residual sensitive byte-copy exposure for callers that pass secret-derived buffers.

#### S2: Resharing accountability closure (culprit aggregation)

Pre-fix issue:
- Selected resharing verification paths contained TODOs and returned on first failure, which prevented reporting of multiple malicious actors in the same failing round.

Implemented fix:
- Added culprit aggregation in the identified round-4 validation paths for both ECDSA and EdDSA resharing.
- Validation now continues through the old-committee share/decommit checks, collects all failing parties, and returns a single wrapped error containing all culprits.
- Added adversarial regression `TestAdversarial_Resharing_MultipleCorruptedSharesReportsMultipleCulprits` to assert multi-culprit reporting for corrupted shares.

Security effect:
- Improves malicious-participant accountability and operator triage in resharing failures.
- Aligns resharing failure reporting with culpability expectations used elsewhere in the codebase.

#### S3: `NewReSharingParameters` missing `newCtx` nil-check

Pre-fix issue:
- `NewReSharingParameters` validated numerical bounds but did not validate `newCtx != nil`, allowing invalid constructor state to pass until later use.

Implemented fix:
- Added explicit fail-fast validation:
  - `if newCtx == nil { return nil, fmt.Errorf(...) }`
- Extended `tss/params_test.go` invalid-case coverage for nil `newCtx`.

Security effect:
- Eliminates a constructor-level configuration footgun.
- Improves deterministic failure behavior and integration safety.

### A.7 Consolidated Finding Status (February 2026)

#### A.7.1 Published Findings (`C1..L3`) Status

| ID | Severity | Finding | Consolidated Status (2026-02-26) |
|---|---|---|---|
| C1 | Critical | Unchecked `ModInverse` nil returns | Fixed |
| C2 | Critical | `NoProofMod` / `NoProofFac` security-proof bypass | Fixed (secure-by-default build gating) |
| H1 | High | Hash errors not propagated (nil return ambiguity) | Mitigated (fail-fast panic; API-breaking error return not adopted) |
| H2 | High | Non-constant-time comparisons in selected paths | Fixed for identified paths in audit scope |
| H3 | High | Incomplete secret memory clearing | Fixed (best-effort zeroization in temp structs) |
| M1 | Medium | Panic-based validation in protocol-critical paths | Fixed for identified paths |
| M2 | Medium | Missing write error checks in tagged hash prelude | Fixed |
| M3 | Medium | Unchecked `GetRandomPositiveInt` nil in callers | Fixed in identified runtime call sites |
| M4 | Medium | Missing ModProof basic property checks | Fixed |
| M5 | Medium | O(n²) padding / memory-copy footprint in signature padding | Fixed (including exported `common.PadToLengthBytesInPlace`) |
| L1 | Low | Signature malleability normalization | Informational positive control |
| L2 | Low | Hardcoded crypto parameters | Informational / accepted risk |
| L3 | Low | Missing threshold parameter validation | Fixed (constructor hardening includes `newCtx` nil-check in resharing path) |

#### A.7.2 Follow-up Findings (`F1..F6`, `S1..S3`) Status

| ID | Severity | Finding | Status |
|---|---|---|---|
| F1 | Critical | Production-accessible proof-disable toggles allow malicious-security downgrade | Fixed |
| F2 | High | CKD malformed extended key accepted, later panic path | Fixed |
| F3 | Medium | Panic-based DoS in selected public/common paths | Fixed (scoped) |
| F4 | Low/Medium | Concurrency validation mismatch leading to panic | Fixed |
| F5 | Medium | Missing negative sign-bit validation on message hash input | Fixed |
| F6 | Medium | `SHA512_256i` nil-pointer panic on nil `*big.Int` input | Fixed |
| S1 | Medium | Residual M5 path in exported `common.PadToLengthBytesInPlace` | Fixed |
| S2 | Low/Operational | Resharing verification accountability TODOs | Fixed |
| S3 | Low | Missing `newCtx` nil validation in `NewReSharingParameters` | Fixed |

### A.8 Consolidated Exploitability Assessment (Post-Remediation)

#### A.8.1 Actor/Capability Model

| Actor | Capability Assumed |
|---|---|
| Internet remote caller | Can send API input but is not an MPC party |
| Authenticated API user | Can trigger protocol operations through service interfaces |
| Malicious MPC participant | Controls one or more protocol participants and message contents |
| Operator / CI pipeline | Controls build tags and deployment configuration |
| Local host attacker | Can inspect process memory or crash process locally |

#### A.8.2 Historical Exploit Set (Now Patched)

| Exploit Class | Was it valid pre-fix? | Impact pre-fix |
|---|---|---|
| Proof-disable downgrade (`SetNoProof*`) + malicious participant | Yes | Protocol security downgrade; increased risk of key-share compromise in adversarial committees |
| Malformed CKD extended key panic path | Yes | Process crash / DoS in parse-then-log/serialize flows |
| Panic-based input/state handling in identified constructor/helper paths | Yes | Process crash / DoS |
| Zero-concurrency panic path | Yes | Process crash / DoS |
| Negative message hash sign-bit bypass | Yes | Signature over wrong message value; silent sign truncation |
| Nil `*big.Int` input to `SHA512_256i` | Yes | Process crash / DoS via nil-pointer panic |
| Residual exported padding utility (`common.PadToLengthBytesInPlace`) | Yes | O(n²) allocation/copy amplification and additional sensitive byte copies in heap |
| Resharing accountability TODO paths | Yes | Partial culprit visibility during malicious multi-party failures |
| Missing `newCtx` constructor validation in resharing params | Yes | Delayed runtime failures from invalid constructor inputs |

#### A.8.3 Valid Exploits in Current Patched Code

| Current Exploit Possibility | Preconditions | Valid Actor | Impact |
|---|---|---|---|
| Re-enable proof bypass via `insecure_noproofs` build tag | Non-default insecure build used in production + adversarial MPC participant | Operator/CI + malicious participant | Security downgrade similar to historical C2/F1 class; potential key-share compromise risk under malicious-party threat |
| Remaining crash risk from non-audit panic-style utility APIs | Application exposes those code paths to attacker-controlled parameters (not shown in this remediation scope) | Authenticated API user / integration bug | Service crash/DoS; no direct key extraction shown from these paths alone |
| Side-channel/in-memory extraction classes | Strong local access, advanced side-channel/memory forensics | Local host attacker | Potential secret leakage is environment-dependent; not a turnkey remote exploit from this audit set |
| ~~Negative message hash sign-bit bypass~~ | ~~Caller supplies negative `*big.Int` as message hash; bypasses `m < N` bounds check~~ | ~~Authenticated API user~~ | ~~Fixed in F5~~ |
| ~~Nil `*big.Int` input to `SHA512_256i`~~ | ~~Caller passes nil element in variadic args; triggers nil-pointer panic~~ | ~~Authenticated API user / integration bug~~ | ~~Fixed in F6~~ |
| ~~Residual exported padding utility (`common.PadToLengthBytesInPlace`)~~ | ~~Caller relies on shared padding helper with sensitive data; loop-prepend creates repeated allocations/copies~~ | ~~Authenticated API user / integration bug~~ | ~~Fixed in S1~~ |
| ~~Resharing accountability TODO paths~~ | ~~Multiple malicious old-committee senders fail in same round~~ | ~~Malicious MPC participant~~ | ~~Fixed in S2~~ |
| ~~Missing `newCtx` validation in `NewReSharingParameters`~~ | ~~Integrator passes nil `newCtx`~~ | ~~Operator / integration bug~~ | ~~Fixed in S3~~ |

#### A.8.4 Key Clarification: Remote Private-Key Extraction

For the patched default build:
- No direct unauthenticated remote private-key extraction path is known from this consolidated finding set.

For explicitly insecure builds:
- If `insecure_noproofs` is enabled and malicious participants are present, private-share compromise risk becomes plausible again because proof enforcement is intentionally disabled.

For upstream behavior prior to this remediation:
- There was no single-step unauthenticated "dump private key" path identified.
- However, the publicly accessible proof-disable toggles created a realistic malicious-party exploitation path to share compromise under adversarial MPC conditions, which can enable private-key reconstruction once threshold requirements are met.

#### A.8.5 Explicit Risk Statement (Upstream vs Current Branch)

1. **Upstream (pre-remediation semantics)**:
   - Key compromise risk was **plausible** when proof-disable controls were active and malicious participants were present.
   - Therefore, it is inaccurate to claim "no exploitable key-reconstruction path" under those conditions.
2. **Current branch (default secure build semantics)**:
   - That proof-bypass path is closed by secure-by-default build gating.
   - From this finding set, there is no clear key-reconstruction path in the default build.
3. **Current branch with `insecure_noproofs` tag**:
   - The historical downgrade risk is intentionally reintroduced and should be treated as unsafe for untrusted production environments.

#### A.8.6 Operational Guardrails Required

1. Enforce build policy in CI to block production artifacts built with `-tags insecure_noproofs`.
2. Restrict MPC participation to authenticated/authorized peers and monitor for malformed proof traffic.
3. Keep panic-to-error hardening as an ongoing effort for any additional externally reachable paths.

### A.9 Validation and Exact Reproduction / Verification Steps

Run from repository root:

```bash
cd <repo-root>
mkdir -p "${TMPDIR:-/tmp}/gocache"
export GOCACHE="${TMPDIR:-/tmp}/gocache"
```

#### A.9.1 Verify F1 fix (secure build blocks proof-disable toggles)

```bash
go test ./tss -run TestSetNoProofBlockedInSecureBuild -count=1 -v
```

Expected:
- Test passes.
- `NoProofMod()` and `NoProofFac()` remain `false` in secure/default builds.

#### A.9.2 Verify F2 fix (malformed CKD input rejected; no panic serialization path)

```bash
go test ./crypto/ckd -run 'TestNewExtendedKeyFromStringRejectsInvalidPoint|TestExtendedKeyStringInvalidStateDoesNotPanic' -count=1 -v
```

Expected:
- Both tests pass.
- Invalid extended-key inputs are rejected.
- Invalid in-memory state no longer panics on `String()`.

#### A.9.3 Verify F3 fixes (no panic in identified invalid-input/state paths)

```bash
go test ./crypto/paillier -run TestGenerateKeyPairOptionalConcurrencyValidation -count=1 -v
go test ./ecdsa/keygen -run 'TestBuildLocalSaveDataSubsetMissingSignerDoesNotPanic|TestNewLocalPartyInvalidOptionalPreParamsDoesNotPanic|TestNewLocalPartyTooManyOptionalPreParamsDoesNotPanic' -count=1 -v
go test ./eddsa/keygen -run TestBuildLocalSaveDataSubsetMissingSignerDoesNotPanic -count=1 -v
```

Expected:
- All tests pass without panic.
- Invalid optional args/mismatch paths are handled safely.

#### A.9.4 Verify F4 fix (zero/invalid concurrency no longer panics)

```bash
go test ./ecdsa/keygen -run TestNewDlnProofVerifierZeroConcurrencyDoesNotPanic -count=1 -v
go test ./tss -run TestSetConcurrencyClampsToMinimum -count=1 -v
```

Expected:
- All tests pass.
- Invalid concurrency values are clamped to `1`.

#### A.9.5 Verify F5 fix (negative message hash rejected)

```bash
go build ./ecdsa/signing/ ./eddsa/signing/
```

Expected:
- Build succeeds; the sign-bit check is present at `ecdsa/signing/round_1.go:40` and `eddsa/signing/round_1.go:32-34`.

#### A.9.6 Verify F6 fix (nil input to `SHA512_256i` does not panic)

```bash
go test ./common/ -run TestSHA -count=1 -v
```

Expected:
- All hash tests pass.
- The nil guard in `SHA512_256i` matches the pattern in `SHA512_256i_TAGGED`.

#### A.9.7 Verify full regression suites used in this audit cycle

```bash
go test ./...
go test -tags insecure_noproofs ./...
```

Expected:
- Both full-suite commands pass on the patched branch.

#### A.9.8 Verify S1 fix (shared padding utility hardening)

```bash
go test ./common -run TestPadToLengthBytesInPlace -count=1 -v
```

Expected:
- Tests pass for padded output correctness, no-op behavior, nil-input behavior, and source-byte zeroization.

#### A.9.9 Verify S2 fix (multi-culprit accountability in resharing)

```bash
go test ./ecdsa/resharing -run TestAdversarial_Resharing_MultipleCorruptedSharesReportsMultipleCulprits -count=1 -v
go test ./ecdsa/resharing ./eddsa/resharing -count=1
```

Expected:
- Adversarial resharing test reports multiple culprits for concurrent malicious share corruption.
- Both resharing package suites pass without regressions.

#### A.9.10 Verify S3 fix (`newCtx` constructor validation)

```bash
go test ./tss -run TestNewReSharingParametersInvalid -count=1 -v
```

Expected:
- Invalid-case tests include and reject nil `newCtx`.

### A.10 MR1 Breaking Changes and Migration Guidance

This section is the authoritative MR1 compatibility note for maintainers and integrators.

#### A.10.1 Compile-time breaking API changes

| API | Previous signature/behavior | Current signature/behavior | Migration action |
|---|---|---|---|
| `tss.NewParameters` (`tss/params.go`) | `func NewParameters(...) *Parameters` | `func NewParameters(...) (*Parameters, error)` with argument validation | Handle returned `error`; ensure valid `threshold`, `partyCount`, and non-nil args |
| `tss.NewReSharingParameters` (`tss/params.go`) | `func NewReSharingParameters(...) *ReSharingParameters` | `func NewReSharingParameters(...) (*ReSharingParameters, error)` with argument validation | Handle returned `error`; validate `newThreshold < newPartyCount` and non-nil args |
| `ecdsa/signing.PrepareForSigning` (`ecdsa/signing/prepare.go`) | Returned `(wi, bigWs)` and panicked on invalid input | Returns `(wi, bigWs, error)` | Update call sites to propagate/handle errors |
| `eddsa/signing.PrepareForSigning` (`eddsa/signing/prepare.go`) | Returned `wi` and panicked on invalid input | Returns `(wi, error)` | Update call sites to propagate/handle errors |

#### A.10.2 Runtime behavior changes with compatibility impact

| Behavior | Previous behavior | Current behavior | Operational impact |
|---|---|---|---|
| `SetNoProofMod()` / `SetNoProofFac()` in default builds | Disabled Paillier proof verification directly | Blocked in secure/default builds; effective only with `-tags insecure_noproofs` | Test or compatibility flows that relied on proof-disable must opt into insecure build tag |
| `GeneratePreParamsWithContextAndRandom(...optionalConcurrency...)` when more than one optional item is passed | `panic` | Returns `error` | Upstream callers expecting panic must switch to normal error handling |
| `common.PadToLengthBytesInPlace` when `len(src) < length` | Loop-prepend allocations; source bytes unchanged | Single-allocation pad; original source bytes are zeroed | Callers that need to retain source bytes should pass a copy |
| `NewReSharingParameters(..., newCtx=nil, ...)` | Could pass constructor and fail later | Fails fast with constructor error | Integrators must always provide non-nil `newCtx` |

#### A.10.3 Migration checklist

1. Update all `NewParameters` and `NewReSharingParameters` call sites to handle `error`.
2. Update direct `PrepareForSigning` calls (ECDSA/EdDSA) to handle `error`.
3. Enforce production build policy to prohibit `-tags insecure_noproofs`.
4. Replace panic-based test assumptions for preparam concurrency validation with error assertions.
5. For `PadToLengthBytesInPlace`, pass a copy if the original source bytes must be preserved post-call.

### A.11 Residual Risk Notes

1. `insecure_noproofs` is intentionally dangerous and must be blocked from production artifacts.
2. Some panic-style helpers (`Must*`) remain by design; only externally reachable crash paths in this audit scope were treated as vulnerabilities.
3. Zeroization in Go remains best-effort due to GC/runtime constraints.
4. Previously open supplemental closure items (`S1..S3`) are resolved in the pre-squash branch state (`690f45a`); for long-term traceability under squash merge, use MR `!1` plus the final squash commit SHA on `main`.

---

## Appendix B: June 2026 Boundary-Validation Update and Remediation

This appendix documents a focused follow-up review performed in June 2026, after two
upstream advisories (`SRC-2026-573`, `SRC-2026-644`) were cross-referenced against this
fork, and a subsequent in-house audit of adversarial input validation at protocol message
boundaries. It follows the same format and conventions as Appendix A and uses the `J`
("June") finding prefix.

### B.1 Metadata

| Field | Value |
|---|---|
| Repository | `github.com/AnvoIO/tss-lib` (v3) |
| Review Date | `2026-06-19` |
| Base | `master` (`2471435`) |
| Reviewed Branch | `security/2026-06-update` |
| Security-fix Commit | `6cfe2d1` (`J1`, `J2`) |
| Hardening Commit | `080b806` (`J3`–`J8`) |
| Upstream Advisories | `SRC-2026-573`, `SRC-2026-644` (`bnb-chain/tss-lib`) |
| Method | Cross-reference of upstream advisories + multi-agent audit of message-boundary input validation, with adversarial verification of every candidate finding |
| **Audit and Fixes By** | Robert Capps - Stratovera LLC \<robert@stratovera.io\> |

### B.2 Executive Summary

Two issues (`J1`, `J2`) were identified by cross-referencing upstream advisories against
this fork's independently-rewritten v3 codebase; both were genuine gaps in our code and are
fixed in `6cfe2d1`. `J2` is a remotely-triggerable denial-of-service: a single malicious
signing participant can crash an honest EdDSA signer with off-curve coordinates. `J1` is a
non-canonical EC point acceptance gap (a `btcec/v2` `IsOnCurve` quirk that silently reduces
out-of-range coordinates mod P).

A subsequent in-house audit fanned out across every protocol message boundary
(ECDSA/EdDSA keygen, signing, resharing) and the cryptographic deserialization surfaces,
specifically targeting the bug class that `J1`/`J2` represent: **use-before-error-check**,
**missing range/canonicality checks**, and **missing nil/length guards on unmarshalled
peer input**. Every candidate finding was adversarially verified (refute-by-default). That
verification found **no further exploitable vulnerability** — a result that corroborates
that `J1`/`J2` were isolated gaps rather than the surface of a deeper hole. It did, however,
surface six defense-in-depth and canonicality issues (`J3`–`J8`), several of them cases
where one code path already enforces a check and a sibling path does not. Consistent with a
"non-exploitable is still a defect" posture, all six are remediated in `080b806`. None of
the `J3`–`J8` changes alters the protocol wire format.

### B.3 Findings (`J1`–`J8`)

| ID | Severity | Finding | Exploit Summary (pre-fix) | Verified Reachability | Final Status |
|---|---|---|---|---|---|
| J1 | High | Non-canonical EC point coordinates accepted in `isOnCurve` (`SRC-2026-573`) | Coordinates ≥ P that fit in 32 bytes are silently reduced mod P by `btcec/v2`, letting non-canonical point encodings pass the curve-equation check | Reachable (peer-supplied points) | Fixed (`6cfe2d1`) |
| J2 | High | EdDSA signing round 3 nil-pointer dereference on off-curve `Rj` (`SRC-2026-644`) | A malicious party sends off-curve decommitment coordinates; `NewECPoint` returns `(nil, err)`, and `Rj.EightInvEight()` is called before the error check, panicking an honest signer (remote DoS) | Reachable (peer-supplied decommitment) | Fixed (`6cfe2d1`) |
| J3 | Low | `eddsa/keygen` round 3 use-before-error-check on `UnFlattenECPoints` | Error from `UnFlattenECPoints` checked after the `EightInvEight()` loop | Not exploitable — `UnFlattenECPoints` returns a `nil` slice on error, so `range` is zero iterations; anti-pattern only | Fixed (`080b806`) |
| J4 | Medium | `ProofBobWCFromBytes` trusts caller-validated length | `ProofBobFromBytes` accepts 10 **or** 12 parts; `ProofBobWCFromBytes` then indexes `bzs[10]`/`bzs[11]`, so a 10-part input would panic | Not reachable via protocol — `SignRound2Message.ValidateBasic` enforces exactly 12 parts first; latent API footgun | Fixed (`080b806`) |
| J5 | Low | `ecdsa/signing` round 9 decommitment guard uses `&&` instead of `\|\|` | `if !ok && len(values) != 4` does not fire when `ok=true` but `len != 4`, then indexes `values[0..3]` | Not reachable — `ValidateBasic` exact-5 + hash verification guarantee `ok ⇒ len==4`; latent OOB, inconsistent with round 5/7 | Fixed (`080b806`) |
| J6 | Low | Resharing saves non-canonical `Xi` (no mod-q reduction) | New-committee `newXi` accumulated with `big.Int.Add` (no `modQ`) and saved unreduced, unlike keygen which reduces `xi mod N` | Not exploitable — VSS `Verify` forces `share ≡ P(i) (mod q)` so the sum stays congruent to the correct key, and all downstream signing reduces mod q; produces non-canonical key shares only | Fixed (`080b806`) |
| J7 | Low | Missing nil-guards on exported proof `Verify()` parameters | `Verify()` methods in schnorr/modproof/dlnproof/mta dereference pointer args (`X`, `V`, `R`, `N`, `h1`, `h2`, `ec`) without nil checks | Not reachable — every argument is non-nil by construction at all protocol call sites (`Unmarshal*` returns non-nil; `ec`/`bigR` are trusted local state) | Fixed (`080b806`) |
| J8 | Low | Missing `[0, q)`/`[0, L)` canonicality checks on peer-supplied scalars | Schnorr proof scalars `T`/`U`, VSS `Share`, and EdDSA signature share `S` accepted without range validation; oversize `S` silently truncated to 32 bytes in encoding | Not exploitable — scalar multiplication reduces mod q so verification equations are unaffected; an out-of-range/truncated `S` yields an invalid aggregate caught by the final `edwards.Verify()`; cosmetic/non-canonical only | Fixed (`080b806`) |

### B.4 Exploitation Summary (Pre-Fix Behavior)

| ID | How it could be exploited | Impact |
|---|---|---|
| J1 | Malicious participant submits a point whose coordinate is ≥ P but < 2^256; `btcec/v2` reduces it mod P and accepts it as on-curve | Acceptance of non-canonical point encodings; defense-in-depth gap against malformed point material |
| J2 | Malicious signing participant sends a round-2 decommitment that opens to off-curve coordinates; honest signer calls `EightInvEight()` on the resulting nil point | Remote denial-of-service: honest EdDSA signer process panics |
| J3 | None — `range` over the `nil` slice returned on error executes zero iterations | No runtime effect; fragility if `UnFlattenECPoints` were later changed to return partial slices |
| J4 | A 10-part `ProofBobWc` would reach `bzs[10]`/`bzs[11]`; blocked today by `ValidateBasic` enforcing exactly 12 | Latent index-out-of-bounds panic if the function is called outside the validated protocol path |
| J5 | A decommitment opening with `ok=true` and `len(values) != 4`; impossible today because `ValidateBasic` pins exactly 5 parts and `DeCommit` verifies the hash | Latent index-out-of-bounds panic if the upstream length guard ever weakens |
| J6 | Malicious old-committee member sends `share = P(i) + k·q`; passes VSS `Verify` and inflates the saved `Xi` representative | Non-canonical secret-share representation; no key corruption (congruence preserved, downstream reduces mod q) |
| J7 | A `nil` pointer reaching a `Verify()` method; not producible from a validated protocol message | Latent nil-pointer panic only if these exported APIs are called directly with nil |
| J8 | Out-of-range `T`/`U`/`Share` (congruent mod q) or oversize `S` (truncated to 32 bytes) | Non-canonical inputs normalized by the group law / caught by final signature verification; no soundness or forgery impact |

### B.5 Fix Matrix

| ID | Status | Fix Summary | Primary Files |
|---|---|---|---|
| J1 | **Fixed** | Reject coordinates outside `[0, P)` in `isOnCurve` before delegating to `IsOnCurve` | `crypto/ecpoint.go:127` |
| J2 | **Fixed** | Check the `NewECPoint(Rj)` error before calling `EightInvEight()` | `eddsa/signing/round_3.go:55-59` |
| J3 | **Fixed** | Move the `UnFlattenECPoints` error check before the `EightInvEight()` loop | `eddsa/keygen/round_3.go:84-90` |
| J4 | **Fixed** | Enforce exactly `ProofBobWCBytesParts` (12) inside `ProofBobWCFromBytes` before indexing | `crypto/mta/proofs.go:154-161` |
| J5 | **Fixed** | Change decommitment guard from `&&` to `\|\|` (matches round 5/7) | `ecdsa/signing/round_9.go:36` |
| J6 | **Fixed** | Accumulate the new share via `modQ.Add` so saved `Xi` is canonical in `[0, q)` | `ecdsa/resharing/round_4_new_step_2.go:174`, `eddsa/resharing/round_4_new_step_2.go:89` |
| J7 | **Fixed** | Add nil-guards to exported `Verify()` parameters | `crypto/schnorr/schnorr_proof.go:56,110`, `crypto/modproof/proof.go:122`, `crypto/dlnproof/proof.go:58`, `crypto/mta/proofs.go:201`, `crypto/mta/range_proof.go:110` |
| J8 | **Fixed** | Reject non-canonical peer scalars: Schnorr `T`/`U` and VSS `Share` in `[0, q)`; EdDSA `S` in `[0, L)` at finalize | `crypto/schnorr/schnorr_proof.go:63,121`, `crypto/vss/feldman_vss.go:100`, `eddsa/signing/finalize.go:35-40` |

### B.6 Detailed Remediation Notes

#### J1: Non-canonical EC point coordinate acceptance (`SRC-2026-573`)

Pre-fix issue:
- `isOnCurve` delegated directly to `elliptic.Curve.IsOnCurve`. The `btcec/v2`
  implementation silently reduces coordinates ≥ P (that fit in 32 bytes) modulo P, so a
  non-canonical encoding of an on-curve point passes the curve-equation check.

Implemented fix:
- Added an explicit `[0, P)` range check on both coordinates in `isOnCurve` before the
  underlying curve check (`crypto/ecpoint.go`). Regression test
  `TestNewECPointRejectsNonCanonicalCoords` rejects `x+P`, `y+P`, and negative coordinates.

Security effect:
- Non-canonical point encodings are rejected at construction (`NewECPoint`), closing the
  defense-in-depth gap for all peer-supplied points.

#### J2: EdDSA signing round 3 nil-pointer dereference (`SRC-2026-644`)

Pre-fix issue:
- `Rj, err := crypto.NewECPoint(...)` was followed immediately by `Rj = Rj.EightInvEight()`
  before the `if err != nil` check. Off-curve coordinates from a malicious party make
  `NewECPoint` return `(nil, err)`, and the method call panics on the nil receiver.

Implemented fix:
- Reordered the error check to precede `EightInvEight()` (`eddsa/signing/round_3.go`).
  Regression test `TestAdversarial_EdDSA_Sign_OffCurveRj` forges a consistent off-curve
  commit/decommit pair so `DeCommit()` succeeds and `NewECPoint` is the gate; it was
  verified to reproduce the nil-pointer panic without the fix.

Security effect:
- Eliminates a single-malicious-party remote denial-of-service against honest EdDSA signers.

#### J3: `eddsa/keygen` use-before-error-check on `UnFlattenECPoints`

Pre-fix issue:
- The error from `UnFlattenECPoints` was checked after a loop that calls `EightInvEight()`
  on each returned point. `UnFlattenECPoints` returns a `nil` slice (never a partial slice)
  on error, so `range` executes zero iterations and no panic occurs — but the ordering is
  the same anti-pattern as `J2` and diverges from the correct ordering in
  `ecdsa/keygen/round_3.go`.

Implemented fix:
- Moved the error check before the loop, matching the ECDSA sibling and the `J2` fix.

Security effect:
- Removes a latent fragility; behavior is unchanged for all current inputs.

#### J4: `ProofBobWCFromBytes` caller-trusted length

Pre-fix issue:
- `ProofBobFromBytes` accepts either 10 or 12 byte-parts (`ProofBob` vs `ProofBobWC`).
  `ProofBobWCFromBytes` called it and then unconditionally read `bzs[10]` and `bzs[11]`,
  so a 10-part input would panic. The protocol path is protected because
  `SignRound2Message.ValidateBasic` enforces exactly 12 parts (`NonEmptyMultiBytes` is an
  exact-length check), but the deserializer trusted its caller.

Implemented fix:
- `ProofBobWCFromBytes` now enforces `NonEmptyMultiBytes(bzs, ProofBobWCBytesParts)` (12)
  before indexing. Regression test `TestProofBobWCFromBytesRejectsShortInput` confirms a
  10-part input returns an error without panicking.

Security effect:
- Removes a latent index-out-of-bounds footgun and makes the deserializer self-validating.

#### J5: `ecdsa/signing` round 9 decommitment guard operator

Pre-fix issue:
- The guard `if !ok && len(values) != 4` only fires when both conditions hold. If a
  decommitment verified (`ok=true`) but returned an unexpected element count, the code would
  index `values[0..3]` and panic. This is unreachable today (`ValidateBasic` pins exactly 5
  parts and `DeCommit` verifies the hash, so `ok ⇒ len==4`), and is inconsistent with the
  correct `||` guards in round 5 and round 7.

Implemented fix:
- Changed `&&` to `||`, matching the sibling rounds.

Security effect:
- Removes a latent index-out-of-bounds panic and aligns the defensive pattern across rounds.

#### J6: Non-canonical `Xi` in resharing

Pre-fix issue:
- New-committee parties accumulated peer-supplied shares with `new(big.Int).Add(newXi,
  sharej.Share)` and saved the result as `Xi` without reducing mod q, unlike keygen which
  saves `Mod(xi, N)`. A malicious old-committee party sending `share = P(i) + k·q` passes
  VSS `Verify` (since `g^(P(i)+k·q) = g^P(i)`) and inflates the saved representative. This is
  not a key-corruption bug — `Verify` forces `share ≡ P(i) (mod q)`, so the sum stays
  congruent to the correct key, and all downstream signing reduces mod q — but the stored
  share is non-canonical.

Implemented fix:
- Accumulate via the existing `modQ` (`modQ.Add`) in both ECDSA and EdDSA resharing round 4,
  so the saved `Xi` is canonical in `[0, q)`, matching keygen. Complemented by the `J8` VSS
  range check, which now rejects an out-of-range share before accumulation.

Security effect:
- Saved key shares are canonical and consistent with the keygen path; defense-in-depth
  against non-canonical share injection.

#### J7: Missing nil-guards on exported proof `Verify()` parameters

Pre-fix issue:
- `ZKProof.Verify`/`ZKVProof.Verify`, `ProofMod.Verify`, `dlnproof.Proof.Verify`,
  `ProofBobWC.Verify`, and `RangeProofAlice.Verify` dereferenced pointer parameters without
  nil checks. At every protocol call site these arguments are non-nil by construction
  (`Unmarshal*` returns non-nil `*big.Int`; `ec` and `bigR` are trusted local state), so no
  protocol path can reach them with nil — but the exported APIs were not defensively guarded.

Implemented fix:
- Added nil-guards for the previously-unchecked parameters (`X`; `V`, `R`; `N`; `h1`, `h2`,
  `N`; `ec`).

Security effect:
- Exported verification APIs now fail closed on nil input instead of panicking if called
  directly outside the validated protocol flow.

#### J8: Non-canonical peer-supplied scalars

Pre-fix issue:
- Schnorr proof scalars `T`/`U`, VSS `Share`, and the EdDSA signature share `S` were
  unmarshalled from peer bytes via `SetBytes` and used without `[0, q)` (resp. `[0, L)`)
  validation. Out-of-range values are congruent mod q to a canonical value, so the
  verification equations still hold (scalar multiplication reduces mod q); an oversize `S`
  is silently truncated to 32 bytes by `bigIntToEncodedBytes` and then caught by the final
  `edwards.Verify()`. No soundness or forgery impact, but the inputs are non-canonical.

Implemented fix:
- Reject `T`/`U` outside `[0, q)` in `schnorr.ZKProof.Verify`/`ZKVProof.Verify`; reject a
  `Share` outside `[0, q)` in `vss.Share.Verify` (a single chokepoint covering keygen and
  resharing); reject `S` outside `[0, L)` in EdDSA `finalize` (also closing the silent
  truncation). Regression tests: `TestSchnorrProofVerifyRejectsNonCanonicalT`,
  `TestVerifyRejectsNonCanonicalShare`; the existing `TestAdversarial_EdDSA_Sign_CorruptedSi`
  now accepts rejection by either the `S` range check or final signature verification.

Security effect:
- Peer-supplied scalars are constrained to their canonical range at the verification
  chokepoints, eliminating non-canonical encodings and the silent `S` truncation path.

### B.7 Consolidated Finding Status (June 2026)

| ID | Severity | Finding | Status |
|---|---|---|---|
| J1 | High | Non-canonical EC point coordinates accepted (`SRC-2026-573`) | Fixed (`6cfe2d1`) |
| J2 | High | EdDSA signing round 3 nil-pointer dereference (`SRC-2026-644`) | Fixed (`6cfe2d1`) |
| J3 | Low | `eddsa/keygen` use-before-error-check on `UnFlattenECPoints` | Fixed (`080b806`) |
| J4 | Medium | `ProofBobWCFromBytes` caller-trusted length (latent OOB) | Fixed (`080b806`) |
| J5 | Low | `ecdsa/signing` round 9 decommitment guard operator (latent OOB) | Fixed (`080b806`) |
| J6 | Low | Non-canonical `Xi` in resharing (no mod-q reduction) | Fixed (`080b806`) |
| J7 | Low | Missing nil-guards on exported proof `Verify()` parameters | Fixed (`080b806`) |
| J8 | Low | Missing `[0, q)`/`[0, L)` canonicality checks on peer scalars | Fixed (`080b806`) |

### B.8 Methodology Note

The `J3`–`J8` set was produced by a multi-agent audit: independent readers swept each
protocol package and the cryptographic deserialization surfaces for the three target
sub-classes (use-before-error-check, missing range/canonicality checks, missing nil/length
guards), and each candidate finding was then handed to an independent adversarial verifier
instructed to refute it by default and confirm reachability against the actual code. The
verification pass downgraded every candidate from "exploitable" to "defense-in-depth /
canonicality only," including two initially rated critical (`J4`, `J6`). No
attacker-reachable vulnerability beyond `J1`/`J2` was found. All findings are nonetheless
remediated, consistent with the project's posture that non-exploitable defects are still
defects.

### B.9 Validation and Verification Steps

Run from repository root:

```bash
cd <repo-root>
mkdir -p "${TMPDIR:-/tmp}/gocache"
export GOCACHE="${TMPDIR:-/tmp}/gocache"
```

#### B.9.1 Verify J1/J2 fixes (point validation + round-3 ordering)

```bash
go test ./crypto -run TestNewECPointRejectsNonCanonicalCoords -count=1 -v
go test ./eddsa/signing -run TestAdversarial_EdDSA_Sign_OffCurveRj -count=1 -v
```

Expected:
- Non-canonical coordinates (`x+P`, `y+P`, negative) are rejected.
- The off-curve `Rj` adversarial test passes (and reproduces a nil-pointer panic if the
  round-3 ordering fix is reverted).

#### B.9.2 Verify J4/J8 fixes (deserializer + scalar canonicality)

```bash
go test ./crypto/mta -run TestProofBobWCFromBytesRejectsShortInput -count=1 -v
go test ./crypto/schnorr -run TestSchnorrProofVerifyRejectsNonCanonicalT -count=1 -v
go test ./crypto/vss -run TestVerifyRejectsNonCanonicalShare -count=1 -v
```

Expected:
- A 10-part `ProofBobWC` input returns an error without panicking.
- A Schnorr proof scalar `T+q` and a VSS share `s+q` (both congruent mod q) are rejected.

#### B.9.3 Verify J3/J5/J6/J7 fixes (compile + protocol regression)

```bash
go build ./...
go test ./ecdsa/signing ./ecdsa/resharing ./eddsa/keygen ./eddsa/resharing -count=1
```

Expected:
- Build succeeds; protocol suites pass with the reordered/guarded code paths.

#### B.9.4 Verify full regression suites for this update cycle

```bash
go test ./...
go build -tags insecure_noproofs ./...
```

Expected:
- Full default-build suite passes; the `insecure_noproofs` build compiles.

### B.10 Residual Risk Notes

1. `J3`–`J8` are defense-in-depth and canonicality fixes; none addresses a demonstrated
   exploitable vulnerability, and none changes the protocol wire format.
2. `J1`/`J2` were genuine gaps unique to this fork's v3 rewrite, identified by
   cross-referencing upstream advisories; integrators on earlier branches should treat the
   `J2` remote-DoS as the priority item.
3. The multi-agent audit scope was message-boundary input validation; it did not re-audit
   the cryptographic-soundness or memory-hygiene domains covered in the February 2026 cycle.
