MODULE = github.com/AnvoIO/tss-lib/v3
PACKAGES = $(shell go list ./... | grep -v '/vendor/')
SIGNING_PACKAGES = ./ecdsa/signing ./eddsa/signing
SIGNING_RACE_REGEX = TestE2E_(SignZeroMessage|SignMaxMessage|ReSignSameKey)|TestE2E_EdDSA_(SignZeroMessage|SignMaxMessage|ReSignSameKey)

all: protob test

########################################
### Protocol Buffers

protob:
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

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test_unit test_unit_race test_signing_race test
