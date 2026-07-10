# Security policy

## Supported versions

Only the latest v3 release receives security fixes. Older releases and the upstream v1/v2 module paths are unsupported.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub Private Vulnerability Reporting for this repository. If that feature is unavailable, contact the maintainer through a previously authenticated private channel and request an encrypted reporting path. Include affected versions, preconditions, impact, a minimal reproducer, and any suggested remediation.

The maintainer will acknowledge reports as soon as practical, coordinate disclosure with the reporter, and credit reporters who want attribution. Cryptocurrency integrations should arrange their own incident-response contact and deployment process; this repository cannot guarantee downstream patch adoption.

## Security assumptions

This library currently targets authenticated, known protocol participants. Authentication does not make peer input structurally safe: every wire message is treated as attacker-controlled for parsing, bounds checking, proof verification, and committee membership.

Applications must provide:

- authenticated and confidential point-to-point transport;
- reliable broadcast or transcript hash comparison;
- a fresh positive session nonce, agreed by every party, for every keygen, signing, and resharing run;
- replay protection and durable session-state tracking;
- protocol timeouts and safe abort handling;
- protected storage and access control for key shares and Paillier pre-parameters.

`ParseWireMessage` rejects messages larger than 4 MiB. Transports should enforce an equal or smaller limit before buffering a complete message.

## Release and maintenance controls

Security-relevant releases should satisfy all of the following:

1. CI passes on supported Go versions and architectures.
2. `go vet`, `govulncheck`, adversarial tests, and applicable race tests pass.
3. A fresh-context review record identifies the reviewed commit and disposition of every finding.
4. API, transcript, wire, and saved-key compatibility are documented.
5. The release is made from the reviewed commit with a signed tag and published checksums.

See [GOVERNANCE.md](./GOVERNANCE.md) for the solo-maintainer review process and required repository settings.

## Audit scope

Audit reports describe the reviewed commit and threat model; they are not a guarantee that later code is secure. Review the linked report, subsequent changelog entries, and your integration-specific assumptions together.
