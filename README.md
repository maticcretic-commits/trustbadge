# TrustBadge 🏅

**One badge. Every check behind it.**

Run the AgentForge family over a project and you get eleven JSON
reports in eleven shapes, each answering one question: did it
leak, did it drift, does the report hold up. Nobody reads eleven
reports. A project lead wants one number and one badge — and wants
to know exactly what arithmetic produced them.

TrustBadge is that arithmetic. It reads a folder of check reports,
normalizes each to (tool, verdict, score), and combines them with
published weights into a single composite trust score, rendered as
a table or as a self-contained SVG badge for your README:

![agent trust](examples/badge.svg)

*(That badge is real: generated from the sample reports in
`examples/reports/` — a project whose outputs fail their contract,
capped at 49. See the example below.)*

Offline and dependency-free: stdlib-only Python, no network, no
account, fully deterministic. Same reports in, same score out.

```bash
python src/trustbadge.py aggregate reports/
python src/trustbadge.py badge reports/ --out badge.svg
python src/trustbadge.py aggregate reports/ --fail-under 70   # CI gate
```

## The commands

| Command | What it does |
|---------|--------------|
| `aggregate <reports-dir>` | Read every `*.json` in the folder, score each recognized check, and print the composite with its coverage. |
| `aggregate … --format json` | Machine-readable report: per-check verdict/score/points/weight, composite, cap status, coverage, the full weights table, and the unrecognized/unreadable/informational file lists. |
| `aggregate … --fail-under N` | Exit `1` if the composite is below `N`. Without it, `aggregate` exits `0` whenever it produced a report — it is a report, not a gate, unless you ask for the gate. |
| `badge <reports-dir> --out badge.svg` | Write a shields-style SVG badge and print the Markdown snippet (`![agent trust](badge.svg)`) to stdout. `--fail-under` works here too. |
| `init` | Scaffold a sample `reports/` folder (four sibling reports: pass / pass / warn / fail) + `EXPECTED.md`, so you can watch the FAIL cap fire. |

Exit codes: `0` = report produced (and at/above `--fail-under`
when given), `1` = below `--fail-under`, `2` = usage or IO error —
including an empty reports folder, or one where *nothing* was
recognized.

## What it reads

TrustBadge never runs the other tools. It reads the JSON they
already wrote — each sibling's `--format json` output, via a
tolerant adapter per shape:

| Check | Report shape it recognizes | Verdict comes from |
|-------|----------------------------|--------------------|
| SecretScan | bare findings list (`[]` = clean) | its own fail-on rule (any high/critical fails); score derived on the family penalty scale (critical −40, high −20, medium −8, low −2) |
| SkillAudit | single audit or `audit-all` (`skills` + `summary`) | native verdict and score (audit-all: worst skill governs) |
| AgentProof | `{repo, checks: [{status}]}` | native statuses: any `fail` fails, any `unknown` warns; score = % checks passed |
| SchemaGuard | `validate` (`summary.pass_rate`) or `diff` (`breaking_count`) | any failed output or breaking change fails; score = pass rate |
| ClaimCheck | `{score, verdict, summary}` | native verdict and score |
| AgentCI | `run` report (`results`) or `compare` (`regressions`) | its own rule: a failed *or missing* case fails the suite; score = % cases passed |
| PromptRE | bare analysis list (`structure_score`) | no native verdict — TrustBadge bands the score (≥80 pass, below warns; **never a derived fail**); worst prompt governs |
| PromptLint | `{results, summary.worst_score}` | native per-file verdicts; worst file governs |
| PromptDiff | `diff` report (`high_risks`) | any high-risk change fails, any risk warns |
| TraceTape | `validate` report (`command: "validate"`) | any invalid or incomplete run fails, warnings warn |
| CostLedger | `tally` ledger (`totals`) or `compare` (`regressed`) | a cost regression fails; incomplete cost (unpriced models), pricing warnings or malformed lines warn |

Informational outputs — a PromptDiff `stats` profile, a TraceTape
`summary` — are recognized but **not scored**: they are listed as
"Not scored", never silently turned into points.

### The `trust-report.json` contract

Any tool — ours or yours — can emit this minimal shape and be
first-class input:

```json
{"tool": "my-check", "verdict": "pass",
 "score": 87, "summary": "3 of 3 gates green"}
```

`tool` (string) and `verdict` (`pass` | `warn` | `fail`, any
case) are required; `score` (0–100 or `null`) and `summary` are
optional. If your tool's name matches a family check, it fills
that check's slot and weight. Any other tool is scored with the
default extra weight (5) and listed as a non-family check — it
influences the composite but never the coverage count.

## Scoring

**Weights** (published here and in every `--format json` report;
they sum to 100, so a full-coverage composite is a plain weighted
average):

| Check | Weight | | Check | Weight |
|-------|-------:|--|-------|-------:|
| SecretScan | 16 | | AgentCI | 10 |
| SkillAudit | 16 | | PromptRE | 5 |
| AgentProof | 12 | | PromptLint | 5 |
| SchemaGuard | 12 | | PromptDiff | 4 |
| ClaimCheck | 12 | | TraceTape | 4 |
| CostLedger | 4 | | *(any other tool)* | *5* |

Security weighs most; proof, schema and claims next; then the
regression suite; then prompt, trace and cost hygiene.

**Points.** A check contributes its native 0–100 score when it
reports one. When it doesn't (CostLedger, TraceTape, PromptDiff…),
its verdict maps to points: pass = 100, warn = 60, fail = 0.

**The FAIL cap.** If *any* scored check failed, the composite is
capped at **49** — no matter how high the weighted average was.
A project leaking secrets does not get a green badge because its
prompts are tidy. The report always shows the raw score next to
the cap, so the arithmetic is never hidden.

**Coverage.** The score is always displayed with the checks that
produced it: `82/100 · 7 of 11 checks`. Missing checks never count
as passes — they only narrow the coverage, and they are listed by
name. A 90 over 3 checks is a weaker claim than an 85 over 11,
and the badge says which one you have.

**Duplicates.** If a folder holds several reports for one tool,
the *worst* counts. A badge must not hide a failing run behind a
passing re-run left in the same folder.

**Unrecognized files** are listed as UNRECOGNIZED, unreadable ones
as UNREADABLE — never silently scored, never silently dropped.

**Badge colours:** capped → red, always. Otherwise: ≥85 green,
70–84 yellow, 50–69 orange, <50 red.

## Example

From `examples/reports/` — a fictional invoicing project that
passes its secret scan and skill audit, has solid claims, but
ships one output that fails its contract:

```
$ trustbadge aggregate examples/reports
====================================================================
TrustBadge — aggregate report
====================================================================
Reports: examples/reports

  check          verdict   score weight  summary
  SecretScan     ✅ PASS     100     16  0 findings
  SkillAudit     ✅ PASS      98     16  skill 'invoice-helper' · 4 file(s) scanned · 1 finding(s)
  AgentProof     ⚠️ WARN      75     12  3/4 checks passed, 1 unknown
  ClaimCheck     ⚠️ WARN      88     12  6 claim(s) · 5 verified · 0 unbacked · 0 mismatched
  SchemaGuard    ❌ FAIL    66.7     12  2/3 outputs valid
  PromptLint     ✅ PASS      96      5  1 prompt(s) linted · worst score 96/100 · 2 finding(s)
  CostLedger     ⚠️ WARN       —      4  23 event(s) · 24,500 tokens — cost incomplete — unpriced model(s): mystery-model-9000
  TraceTape      ⚠️ WARN       —      4  1 tape(s) · 23 event(s) · 0 error(s) · 1 warning(s)

Composite: 49/100 · 8 of 11 checks
⚠️ Capped at 49: SchemaGuard FAILED — raw weighted score was 85. A failed check caps the badge; fix the failure, not the arithmetic.
Not run: AgentCI, PromptDiff, PromptRE — missing checks never count as passes; they only narrow the coverage.
```

The raw weighted score is 85 — a decent project with one broken
output file. The composite is 49, because one check failed and
the cap is the whole point: the badge a stranger sees must not
say "basically fine" about a project shipping invalid outputs.

## Dogfood: the family's own badge

`examples/reports-real/` holds three reports produced by running
the siblings over AgentForge's *own* artifacts, published
unedited (full provenance in its `PROVENANCE.md`). The short
version: SecretScan flags its own detector fixtures (the AWS
documentation example in its config template), PromptLint fails
PromptRE's example prompt on a contradiction *candidate*, and
TraceTape's own tape validates clean — composite **49 · 3 of 11
checks**, capped. That is the honest self-portrait, and
publishing it as-is is the point of the tool.

## What TrustBadge does NOT do

- **It does not run the checks.** It aggregates reports the
  siblings already produced. A stale report scores exactly like a
  fresh one — freshness is your pipeline's job.
- **It does not make a failed thing pass.** The cap is a rule,
  not a rounding choice, and the raw score is always printed
  beside it so you can see precisely what the cap cost.
- **It does not guess at unknown JSON.** A file it cannot
  recognize is listed as UNRECOGNIZED. If your tool's output
  isn't scored, the report says so — emit the `trust-report.json`
  shape above and it will be.
- **It does not average away coverage.** Eleven tools exist; a
  badge built from three of them says "3 of 11" on its face.

## Quick start

```bash
# 1. Scaffold the sample reports and watch the cap fire:
trustbadge init
trustbadge aggregate reports        # Composite: 49 (raw 79.0, capped)

# 2. Score your own run: collect the family's JSON in one folder:
secretscan scan . --format json        > reports/secretscan.json
schemaguard validate outputs --schema contract.json \
    --format json                      > reports/schemaguard.json
trustbadge aggregate reports --fail-under 70

# 3. Put the badge in your README:
trustbadge badge reports --out badge.svg   # prints ![agent trust](badge.svg)
```

## Part of AgentForge

TrustBadge is the twelfth tool in the [AgentForge](https://github.com/maticcretic-commits)
trust layer for AI agents:

- **AgentProof** — verify agent work — [github.com/maticcretic-commits/agentproof](https://github.com/maticcretic-commits/agentproof)
- **PromptRE** — reverse-engineer agent prompts — [github.com/maticcretic-commits/promptre](https://github.com/maticcretic-commits/promptre)
- **AgentCI** — regression harness for agents — [github.com/maticcretic-commits/agentci](https://github.com/maticcretic-commits/agentci)
- **SecretScan** — scan agent outputs for leaked secrets — [github.com/maticcretic-commits/secretscan](https://github.com/maticcretic-commits/secretscan)
- **CostLedger** — cost accounting for agent runs — [github.com/maticcretic-commits/costledger](https://github.com/maticcretic-commits/costledger)
- **SchemaGuard** — validate agent outputs against their contracts — [github.com/maticcretic-commits/schemaguard](https://github.com/maticcretic-commits/schemaguard)
- **SkillAudit** — audit agent skills for hidden instructions and quality — [github.com/maticcretic-commits/skillaudit](https://github.com/maticcretic-commits/skillaudit)
- **PromptDiff** — diff prompt versions — [github.com/maticcretic-commits/promptdiff](https://github.com/maticcretic-commits/promptdiff)
- **TraceTape** — the canonical run tape — [github.com/maticcretic-commits/tracetape](https://github.com/maticcretic-commits/tracetape)
- **PromptLint** — lint prompts for quality defects — [github.com/maticcretic-commits/promptlint](https://github.com/maticcretic-commits/promptlint)
- **ClaimCheck** — audit agent reports against their evidence — [github.com/maticcretic-commits/claimcheck](https://github.com/maticcretic-commits/claimcheck)
- **TrustBadge** — one trust score and badge for the whole family (this repo)

AgentProof checks what an agent *did*; PromptRE checks what it was *told*; AgentCI checks it still *works* after you change it; SecretScan checks that nothing *leaked*; CostLedger checks what it *cost*; SchemaGuard checks the output still *fits the contract*; SkillAudit checks the skill was *safe to install*; PromptDiff checks what the prompt change *changed*; TraceTape keeps the whole run on *tape*; PromptLint keeps the prompt itself *linted clean*; ClaimCheck makes sure every claim is *backed*; TrustBadge puts the family's score *on one badge*.

## License

MIT
