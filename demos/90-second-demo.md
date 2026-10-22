# TrustBadge — 90-second demo script (PREP ONLY — not published)

Status: launch prep for item 19. Record only when the launch is
approved; nothing here is public yet.

**Premise (one line, on camera):** "Eleven verification tools, one
number — and the number refuses to flatter you."

**Setup (before recording):** clone of the trustbadge repo; the
bundled `examples/reports-real/` folder (real reports from the
family's own tools, with PROVENANCE.md). Terminal at 120% font.

---

### Beat 1 — The problem (0:00–0:20)

Narration: "Every AgentForge tool gives its own verdict — secrets,
prompts, tapes, claims. Nobody reads eleven reports. TrustBadge
reads them for you and puts one score on the badge."

On screen: `ls trustbadge/examples/reports-real/` →
`promptlint.json  secretscan.json  tracetape.json  PROVENANCE.md`

### Beat 2 — The aggregate (0:20–0:55)

```bash
$ trustbadge aggregate examples/reports-real
#   check          verdict   score weight  summary
#   SecretScan     ❌ FAIL      40     16  2 finding(s): 1 critical, 1 high
#   PromptLint     ❌ FAIL      79      5  1 prompt(s) linted · worst score 79/100
#   TraceTape      ✅ PASS       —      4  1 tape(s) · 17 event(s) · 0 error(s)
#
# Composite: 49/100 · 3 of 11 checks
```

(Real captured output, column spacing trimmed.)

### Beat 3 — The cap (0:55–1:20)

Narration: "The raw weighted score was 57.4. The badge says 49 —
because a check FAILED, and a failed check caps the badge. Missing
checks never count as passes either; they only narrow the
coverage. The badge links to the full report, so the number can
always be audited — it is a summary, never a guarantee."

On screen, the aggregate's own words:

```
# ⚠️ Capped at 49: SecretScan, PromptLint FAILED — raw weighted
# score was 57.4. A failed check caps the badge; fix the failure,
# not the arithmetic.
# Not run: AgentCI, AgentProof, ClaimCheck, CostLedger, PromptDiff,
# PromptRE, SchemaGuard, SkillAudit — missing checks never count as
# passes; they only narrow the coverage.
```

### Beat 4 — The badge (1:20–1:30)

```bash
$ trustbadge badge examples/reports-real --out badge.svg
```

Narration: "One SVG for the README, every check behind it.
TrustBadge — the family's score, on one badge." End card with the
repo URL (added at launch, not before).
