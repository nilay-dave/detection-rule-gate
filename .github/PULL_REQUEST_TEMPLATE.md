## What this changes

## Why

## If this adds or changes a check

- [ ] Rationale is written for someone whose pull request it has just blocked
- [ ] Fixture that raises it, and the negative case that must not
- [ ] Firing rate measured on the pinned corpus (`make corpus && make bench`)
- [ ] Severity follows from that rate, not from how serious the finding sounds
- [ ] Any findings that turned out to be correct Sigma are written up in `docs/false-positives.md`
- [ ] `make docs` run, so `docs/checks.md` matches the registry

## Checks

- [ ] `make verify` passes
- [ ] Published numbers carry a marker and match `docs/metrics.json`
- [ ] CHANGELOG updated, with the version bump the change actually warrants
