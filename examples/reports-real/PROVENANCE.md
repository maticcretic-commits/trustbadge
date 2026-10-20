# Provenance — the family's own reports, unedited

These three reports are real output, produced on 2026-10-20 by
running the siblings over AgentForge's own artifacts. They are
published unedited — including the unflattering parts, which are
explained below, not hidden.

```bash
# 1. SecretScan over all eleven siblings' source files
#    (src/*.py of every tool, staged in one folder):
secretscan scan family-src --format json        -> secretscan.json

# 2. PromptLint over PromptRE's example prompt:
promptlint lint promptre/examples/support-agent-prompt.md \
    --format json                               -> promptlint.json

# 3. TraceTape over its own example tape:
tracetape validate tracetape/examples/good.jsonl \
    --format json                               -> tracetape.json
```

## What the findings actually are

- **SecretScan — FAIL (2 findings, both in `secretscan.py`
  itself).** Line 263 is a code comment that quotes the literal
  text `aws_secret_access_key = ...` to explain a detector rule;
  line 551 is the sample config template embedding AWS's
  published documentation example key. SecretScan flags its own
  fixtures — the documented false-positive class for scanner
  tools (GitHub's scanner raised the same alert on this repo
  family; it was resolved as `used_in_tests`). The output is real;
  the secrets are not.
- **PromptLint — FAIL (79/100).** PromptRE's example prompt trips
  a contradiction *candidate* (two hard-rule lines with opposite
  polarity on a shared topic — a heuristic flag for human review,
  exactly as PromptLint labels it) and one medium
  unverifiable-ask finding. A FAIL from a candidate is
  conservative; that is the linter's stated behaviour.
- **TraceTape — PASS.** Its own example tape validates clean:
  17 events, 0 errors.

## The aggregate

```
Composite: 49/100 · 3 of 11 checks (raw 57.4, capped — two FAILs)
```

That is the honest self-portrait: three checks run, two of them
red for explainable reasons, eight not run at all. Publishing it
as-is is the point of the tool.
