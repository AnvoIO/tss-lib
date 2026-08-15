MODULE = github.com/AnvoIO/tss-lib/v4
PACKAGES = $(shell go list ./... | grep -v '/vendor/')
# The version that generated every .pb.go currently in the tree. protoc runs
# whichever protoc-gen-go is on PATH, so a different one silently rewrites all
# eight of them. Refuse rather than regenerate: a wrong answer here is silent.
PROTOC_GEN_GO_VERSION = v1.36.11
SIGNING_PACKAGES = ./ecdsa/signing ./eddsa/signing
SIGNING_RACE_REGEX = TestE2E_(SignZeroMessage|SignMaxMessage|ReSignSameKey)|TestE2E_EdDSA_(SignZeroMessage|SignMaxMessage|ReSignSameKey)|TestUpdateRejectsOutsiderWithoutClearingSensitiveData|TestE2EConcurrent(InvalidSender|MalformedWire)Validation
LIFECYCLE_RACE_PACKAGES = ./tss ./eddsa/signing
LIFECYCLE_RACE_REGEX = TestFatalUpdateTerminalizesBeforeQueuedUpdateRuns|TestParameterIdentitySnapshotsAreRaceSafe|TestE2EConcurrent(InvalidSender|MalformedWire)Validation
RESHARE_PACKAGES = ./ecdsa/resharing ./eddsa/resharing
RESHARE_DUAL_REGEX = TestResharing_DualCommitteeMember

all: protob test

########################################
### Protocol Buffers

check_protoc_gen_go:
	@have=$$(protoc-gen-go --version 2>/dev/null | awk '{print $$2}') ; \
	if [ "$$have" != "$(PROTOC_GEN_GO_VERSION)" ] ; then \
		echo "protoc-gen-go $(PROTOC_GEN_GO_VERSION) is required to regenerate; found $${have:-none}." ; \
		echo "Generating with another version rewrites all eight .pb.go files." ; \
		echo "  go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)" ; \
		echo "If you are deliberately moving to a new version, update PROTOC_GEN_GO_VERSION" ; \
		echo "in the Makefile in the same commit as the regenerated files." ; \
		exit 1 ; \
	fi

protob: check_protoc_gen_go
	@echo "--> Building Protocol Buffers"
	@for protocol in message signature ecdsa-keygen ecdsa-signing ecdsa-resharing eddsa-keygen eddsa-signing eddsa-resharing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./protob/$$protocol.proto ; \
	done

build: protob
	go fmt ./...

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m -race $(PACKAGES)

test_signing_race:
	@echo "--> Running Signing Race Regression Tests"
	go clean -testcache
	go test -timeout 60m -race -count=1 $(SIGNING_PACKAGES) -run "$(SIGNING_RACE_REGEX)"

test_lifecycle_race:
	@echo "--> Stressing Party Lifecycle Race Regressions"
	go clean -testcache
	go test -timeout 60m -race -count=10 $(LIFECYCLE_RACE_PACKAGES) -run "$(LIFECYCLE_RACE_REGEX)"

test_reshare_failopen:
	@echo "--> Fail-open check for the bnb-chain/tss-lib#128 dual-committee fix"
	@echo "    [1/2] fix ENABLED: dual-committee tests must PASS"
	go clean -testcache
	go test -timeout 10m -count=1 $(RESHARE_PACKAGES) -run "$(RESHARE_DUAL_REGEX)"
	@echo "    [2/2] fix DEFANGED (-tags defang_selfshare_128): each package's dual-committee tests must FAIL"
	go clean -testcache
	@for pkg in $(RESHARE_PACKAGES); do \
		echo "    defang: $$pkg must go red"; \
		if go test -timeout 10m -count=1 -tags defang_selfshare_128 $$pkg -run "$(RESHARE_DUAL_REGEX)" >/dev/null 2>&1; then \
			echo "!!! FAIL-OPEN BROKEN in $$pkg: dual-committee tests PASSED with the #128 fix defanged — they would not catch a regression"; \
			exit 1; \
		else \
			echo "    OK: $$pkg went red with the fix defanged"; \
		fi; \
	done
	@echo "--> Fail-open verified: the dual-committee tests detect a regressed #128 fix"

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: check_protoc_gen_go protob build test_unit test_unit_race test_signing_race test_lifecycle_race test_reshare_failopen test
