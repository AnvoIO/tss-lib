## Summary

Describe the change and the protocol or primitive it affects.

## Security impact

- [ ] I identified affected trust boundaries, secret values, transcript inputs, and message indexes.
- [ ] I considered malformed authenticated-peer input, replay/cross-session behavior, and abort cleanup.
- [ ] I considered concurrent valid/invalid message delivery, round advancement, and status/error paths.
- [ ] I added a regression or adversarial test for each security-relevant behavior change.
- [ ] I documented any API, wire, transcript, or saved-key compatibility impact.

## Verification

- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] `go tool govulncheck ./...`
- [ ] `gofmt` is clean

## Review record

For cryptographic or protocol changes, link or paste a fresh-context review record. A solo maintainer may use a second review tool, but must record:

- reviewed commit SHA;
- tool/model and date;
- exact review scope;
- findings and their disposition;
- tests added to make the conclusion reproducible.

Do not describe an AI/tool pass as human review. Tool agreement is supporting evidence, not a substitute for tests or an external cryptographic audit.

## Release checklist (if applicable)

- [ ] Changelog and migration notes updated.
- [ ] Security advisories/report references updated.
- [ ] Release tag will be signed and created from the reviewed commit.
