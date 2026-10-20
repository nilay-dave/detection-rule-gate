# ADR-002: Use libyaml when it is present, and prove the two loaders agree

Status: accepted
Date: 2026-10-20

## Context

The gate runs on every pull request that touches detection content, so its
runtime is a cost paid continuously by every engineer on the team rather than
once by whoever installed it.

A profile of a run over the pinned public corpus of 3,799 rules, taken before
any attempt to make it faster, put the time almost entirely in one place:

```
   ncalls  tottime  cumtime  function
        1    0.191   26.678  engine.run
     3799    0.041   24.551  rules.marks.load
     3799    0.014   22.760  yaml.composer.get_single_node
  1847463    1.525   16.646  yaml.scanner.check_token
   355600    0.886   12.310  yaml.scanner.fetch_more_tokens
```

24.5 of 26.7 seconds was inside `marks.load`, and 22.8 of that was PyYAML's
pure Python scanner and composer. Not one check appeared in the top eighteen
entries, and neither did the condition parser, which three separate checks each
call on the same string. The redundant condition parsing that looked like the
obvious inefficiency was not worth finding.

## Decision

Load with `yaml.CSafeLoader`, the libyaml binding, when it is available, and
fall back to `yaml.SafeLoader` when it is not.

## Consequences

Measured over five passes on the same corpus and the same machine:

| loader | median | spread | rules/s | per 1000 rules |
| --- | --- | --- | --- | --- |
| SafeLoader (pure Python) | 8.557s | 8.211s to 8.632s | 444 | 2.252s |
| CSafeLoader (libyaml) | 1.594s | 1.497s to 1.831s | 2,383 | 0.420s |

5.4 times faster, with findings byte for byte identical: 1,439 before, 1,439
after. Peak memory was unchanged at roughly 85 MiB, so this bought time without
spending space.

The fallback is not decoration. libyaml is absent on plenty of machines, and a
gate that only works where it is installed is worse than a gate that is slower,
because the failure arrives as a confusing install error rather than as a
longer run. The fallback is exercised by the test suite rather than assumed.

## The risk this change actually carried

The speed was never the question. The question was whether the two loaders
report the same positions, because every finding this tool emits is anchored to
a line and a loader that numbered lines differently would move every annotation
in a pull request to the wrong place. That is a correctness bug wearing a
performance change as a disguise, and it would not show up in any test of
whether the findings were right.

So the two are compared rather than trusted:

- Across all 3,799 rules of the pinned corpus, both loaders produce identical
  mark indexes, identical constructed data and identical duplicate key records.
  0 mismatches of 3,799 files compared.
- On every fixture in this repository, the same comparison runs in the test
  suite on every commit, including the fixtures that fail to parse, where the
  reported line number is compared too.
- The five classes of parse failure (an unprintable byte, bad indentation, a
  multi document stream, an empty document, an unresolvable tag) produce the
  same exception class, the same markedness and the same reported line under
  both loaders.

One of those tests asserts that libyaml is present in the environment the suite
runs in. Without it the comparisons compare a loader with itself and prove
nothing, and a vacuous test that passes is worse than no test.

## Alternatives considered

**Cache the parsed condition.** The suspicion before profiling was that three
checks re-parsing the same condition string was the cost. The profile shows the
condition parser is not in the top eighteen entries, so this would have been
work spent on something that was never slow. Left alone, and the independence
of the checks is worth more than the saving would have been.

**Require libyaml.** Would remove the fallback and its tests. Rejected: it
moves a performance concern into an installation failure, and on a composite
action that installs on every run it would make the gate fail on runners where
the wheel is unavailable.

**Parse only the files a pull request changed.** A real and much larger saving,
and the right thing eventually. Rejected for this version because the
duplicate identifier check needs every rule at once, so a changed files mode
has to decide what it means for a corpus scope check, and that question
deserves its own decision rather than being settled in a performance commit.
