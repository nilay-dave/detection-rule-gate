# What the checks got wrong, and how that was found

A linter is judged on the findings it does not raise. The firing rates in
[checks.md](checks.md) are measured automatically and reproduce on every run;
whether each finding is *correct* cannot be measured and was assessed by hand,
one rule at a time, against the pinned public corpus of 3,799 Sigma rules.

Three of the original check designs were wrong. All three were wrong in the
same direction: they flagged correct Sigma, and the only way to find out was to
read every finding. That is written up here rather than quietly fixed, because
the failure rate of a check is the number that decides whether a team keeps the
gate turned on, and a tool that does not publish it is asking to be trusted on
the strength of its own description.

## 1. The wildcard check: 9 findings, 8 of them wrong

The first version flagged any value that was a bare asterisk. It raised 9
findings across 8 files. Reading all 9:

| rule | the selection | verdict |
| --- | --- | --- |
| `kubernetes_audit_hostpath_mount` | `verb: create`, `objectRef.resource: pods`, `hostPath: '*'` | correct Sigma |
| `kubernetes_audit_privileged_pod_creation` | `verb: create`, `objectRef.resource: pods`, `capabilities: '*'` | correct Sigma |
| `aws_ec2_vm_export_failure` | `errorMessage\|contains: '*'` inside `filter1` | correct Sigma |
| `aws_ec2_vm_export_failure` | `errorCode\|contains: '*'` inside `filter2` | correct Sigma |
| `aws_new_lambda_layer_attached` | two named fields plus `requestParameters.layers\|contains: '*'` | correct Sigma |
| `aws_rds_change_master_password` | two named fields plus `masterUserPassword\|contains: '*'` | correct Sigma |
| `win_security_petitpotam_susp_tgt_request` | `EventID: 4768`, `TargetUserName\|endswith: $`, `CertThumbprint\|contains: '*'` | correct Sigma |
| `win_security_susp_ldap_dataexchange` | `EventID: 5136`, an attribute name list, `AttributeValue\|contains: '*'` | correct Sigma |
| `posh_pm_alternate_powershell_hosts` | `ContextInfo\|contains: '*'` and nothing else | worth raising |

Eight of the nine are the same idiom. In Sigma, `field: '*'` is how you say
*this field is present and not empty*. It is a constraint, not an absent one,
and it is the only way to express a field existence test in rules written
before the `exists` modifier was widely supported. Flagging it is flagging
correct content.

The two AWS filter cases are worse than merely wrong. Those wildcards sit
inside selections that the condition subtracts: `selection and not 1 of
filter*`. A wildcard there *excludes* every event that has the field populated.
The check was reporting, as too broad, two rules that the construct made
narrower.

An 89% false positive rate is not a check that needs tuning. It is a check
whose first lesson to a team is which flag turns the gate off.

### What the check does now

A finding is raised only when both of these hold:

1. The condition makes the selection sufficient on its own. Evaluated by
   parsing the condition into a tree and asking whether it holds with that
   selection true and every other selection false, which is the state of an
   event that matches the selection and trips none of the rule's filters.
2. Every constraint in that selection is unbounded. One wildcard among three
   named fields is an existence test; a selection whose only constraint is a
   wildcard matches everything the log source emits.

The first condition is what rules out the negated filters. The second is what
rules out the existence idiom. Both were needed; either alone still gets the
wrong answer on part of the set above.

On the same corpus the check now raises **1** finding, the last row of the
table. That rule's only positive constraint is that `ContextInfo` is not empty,
subtracting an allowlist of known PowerShell hosts. It matches every event in
its log source minus that list, which is a deliberate design for that kind of
detection and still a thing the author should have to state out loud. That is
what suppressions with a mandatory reason are for, and
`tests/fixtures/clean/allowlist_with_suppression.yml` is that rule's shape with
the reason written down.

## 2. The modifier check: 3 findings, all wrong

The first version checked field modifiers against a set I wrote from memory. It
raised 3 findings, all of them `TargetFilename|re|i` or `CommandLine|re|i`, and
all three were valid: `i`, `m` and `s` are sub-modifiers of `re` in the Sigma
specification, and my set did not have them.

An allowlist written from memory is a false positive generator with a delay
built in. The set is now transcribed from the specification appendix at the
commit recorded in [sources.md](sources.md), which also turned up that `gzip`,
which I had assumed was a modifier, is not one.

The check now raises 0 findings on the corpus, and it knows that `i` is valid
only directly after `re`, so a bare `CommandLine|i` is still caught.

## 3. The placeholder check: never shipped

A planned check looked for unreplaced `%placeholder%` tokens. Counting them
across the corpus first:

```
     15 %COMSPEC%        12 %temp%        11 %AppData%      6 %dc_machine_accounts%
     13 %tmp%            12 %Public%       8 %systemroot%   6 %dc_ip_addresses%
```

Most are Windows environment variables being matched deliberately in a command
line. Only the last two are Sigma placeholders, and those are correct as
written: a placeholder is resolved by the processing pipeline at deploy time,
so finding one in source is not a finding at all.

The check was dropped before it was written. The effort went into the modifier
check instead, which catches a failure that is genuinely silent.

## Why the error severity checks all report zero

Six checks fire on nothing in this corpus: both condition checks, both
duplicate checks, `missing-rule-id` and `unknown-field-modifier`. That is the
correct result, not a sign they do not work. SigmaHQ runs its own validation in
CI, so content that reaches the published corpus has already had every one of
these caught.

They are not there for SigmaHQ's corpus. They are there for the fork a team
maintains, where rules are copied as starting points, identifiers are left
behind, modifiers are typed from memory and nobody runs SigmaHQ's CI. Each one
is exercised by a fixture in `tests/fixtures/violations/`.

## How to reproduce any of this

```bash
make corpus          # fetch the corpus at the pinned commit
make bench           # firing rates and throughput into docs/metrics.json
drg check .corpus/sigma/rules --fail-on off --rationale
```

The corpus pin only moves in a commit that also updates `docs/metrics.json`, so
the numbers and the content they were measured against cannot drift apart.
