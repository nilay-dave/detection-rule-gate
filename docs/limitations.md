# What this does not do

Each entry says what triggers building it, so the list is a set of decisions
rather than a set of excuses.

## Multi document rule collections

Sigma allows several documents in one file, with `action: global` sharing
fields across them. This tool raises `rule-unparseable` on such a file rather
than linting the first document and reporting the file as clean, which would
pass a file whose second half was never read.

The pinned corpus of 3,799 rules contains none, so the handling is covered by
fixtures only.

**Trigger:** the first rule corpus this is pointed at that uses them.

## Correlation rules

Sigma correlation rules describe a relationship between other rules rather than
a detection over events. They have their own specification, their own keys, and
none of the checks here apply to them. They parse as `rule-invalid`, which is
accurate but unhelpful.

The pinned corpus contains none.

**Trigger:** the same, plus a decision about what any of these checks would
even mean for a correlation rule.

## Field name validation

The tool does not know whether `TargetFilename` exists in the log source a rule
declares. A misspelled field is as silent as a misspelled modifier and a good
deal more common, and catching it would be the single most valuable check here.

It needs a field taxonomy per log source, the SigmaHQ logsource guides are the
obvious source, and the hard part is not the data but what to do when a team's
pipeline renames fields. A check that fires on every rule in an estate with a
field mapping layer is the false positive problem from
[false-positives.md](false-positives.md) again, at a larger scale.

**Trigger:** a design for reading the field mapping out of a pipeline config,
rather than guessing at it.

## Changed files only

Every run reads every rule under the given paths. On the pinned corpus that is
1.6 seconds for 3,799 rules, so the saving would be small for most teams.

The real obstacle is that `duplicate-rule-id` has a corpus scope and cannot see
a clash against a rule that is not in the set being checked. A changed files
mode has to decide what a corpus scope check means when the corpus is a diff,
and that deserves its own decision rather than being settled inside a
performance change.

This already affects the pre-commit hook, which is passed only staged files and
therefore cannot catch a duplicate identifier against an unstaged rule. That is
why CI runs the whole tree as well.

**Trigger:** a corpus over about 20,000 rules, where a full run stops being
cheap enough to ignore.

## Autofix

Several findings are mechanical: a missing identifier can be generated, and a
tactic tag could be paired with its technique from a lookup table.

Not in this version. An autofix that writes to detection content is a tool that
edits the thing a team is paid to be careful about, and the first version of
the wildcard check in this repository would have been confidently wrong on
eight rules out of nine. An autofix built on a check that has not earned trust
yet is a way of propagating a mistake faster.

**Trigger:** a rule corpus over 200 rules where the mechanical findings are the
bulk of the backlog, and at least one release where the relevant checks raised
no false positives.

## Severity by rule directory

A team usually wants stricter rules for production content than for a
scratch directory. Right now `exclude` is all or nothing per path.

**Trigger:** asked for once by anyone with a directory layout this does not
serve.

## Backends

The tool does not convert rules, and does not check that a rule converts. A
rule that passes every check here can still fail in `sigma convert` for reasons
specific to a backend. That is pySigma's job and it is good at it; running both
is the right answer, and this gate is the cheaper of the two to run on every
commit.
