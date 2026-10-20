# Security policy

## Reporting

Report a vulnerability through GitHub's private vulnerability reporting on this
repository, under Security, rather than by opening an issue. Expect an
acknowledgement within three working days.

## What is in scope

This tool parses untrusted YAML, since a Sigma rule in a pull request is
attacker influenced content on a build runner with a token.

- The loader is `yaml.SafeLoader` or its libyaml equivalent, never
  `yaml.load` with the full constructor set. A rule carrying
  `!!python/object:os.system` is a parse error, and there is a test for that
  under both loaders.
- No rule content is passed to a shell, a template engine or an eval.
- A malformed rule produces a finding, not an exception. One bad file does not
  end the run, and that behaviour has a regression test, because it was broken
  once by a parse error raised while the loader was being constructed.
- The composite action uses no third party action, so nothing outside this
  repository runs with the caller's token.

## What is out of scope

- Findings the tool fails to raise. A missed finding is a correctness bug, and
  `docs/false-positives.md` says plainly what the checks do not catch.
- The rule corpus fetched by `tools/fetch_corpus.py`. It is third party content
  pinned to a commit, it is never executed, and it is not vendored.

## Supported versions

The most recent minor release.
