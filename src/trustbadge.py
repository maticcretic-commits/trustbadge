#!/usr/bin/env python3
"""
TrustBadge — "One badge. Every check behind it."

Eleven AgentForge tools each answer one question about an agent and
its work — did it leak, did it drift, does the report hold up. Run
them all and you get eleven JSON reports in eleven shapes. Nobody
reads eleven reports. A project lead wants one number and one
badge, and wants to know exactly what arithmetic produced them.

TrustBadge is that arithmetic. It reads a folder of JSON reports —
the `--format json` output of any AgentForge sibling, or any file in
the minimal `trust-report.json` shape documented in the README —
normalizes each one to (tool, verdict, score), and combines them
with published weights into one composite:

    trustbadge aggregate <reports-dir> [--format text|json]
                                       [--fail-under N]
    trustbadge badge <reports-dir> --out badge.svg [--fail-under N]
    trustbadge init

The rules are strict about honesty:

- A FAILED check caps the composite at 49. A project leaking
  secrets does not get a green badge because its prompts are tidy.
- Missing checks never count as passes. The score is always shown
  with its coverage: "82/100 · 7 of 11 checks".
- Files TrustBadge cannot recognize are listed as UNRECOGNIZED —
  never silently scored, never silently dropped.

Offline and dependency-free: stdlib-only Python, no network, no
account, fully deterministic. Same reports in, same score out.
"""

import argparse
import json
import sys
from pathlib import Path

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# The family: eleven checks, published weights (they sum to 100, so a
# full-coverage composite is a plain weighted average). Security checks
# weigh most; then proof / schema / claims; then the regression suite;
# then prompt, trace and cost hygiene.
# ---------------------------------------------------------------------------

WEIGHTS = {
    "secretscan": 16,
    "skillaudit": 16,
    "agentproof": 12,
    "schemaguard": 12,
    "claimcheck": 12,
    "agentci": 10,
    "promptre": 5,
    "promptlint": 5,
    "promptdiff": 4,
    "tracetape": 4,
    "costledger": 4,
}
EXTRA_WEIGHT = 5          # a generic trust-report from a non-family tool
FAIL_CAP = 49             # any FAIL caps the composite here
DISPLAY = {
    "agentproof": "AgentProof", "promptre": "PromptRE",
    "agentci": "AgentCI", "secretscan": "SecretScan",
    "costledger": "CostLedger", "schemaguard": "SchemaGuard",
    "skillaudit": "SkillAudit", "promptdiff": "PromptDiff",
    "tracetape": "TraceTape", "promptlint": "PromptLint",
    "claimcheck": "ClaimCheck", "trustbadge": "TrustBadge",
}
VERDICT_EMOJI = {"pass": "✅", "warn": "⚠️", "fail": "❌"}
VERDICT_POINTS = {"pass": 100.0, "warn": 60.0, "fail": 0.0}
VERDICT_RANK = {"pass": 0, "warn": 1, "fail": 2}
# SecretScan findings -> score penalties (the scale SkillAudit uses).
SEV_PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 2,
               "info": 0}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class UsageError(Exception):
    """Raised for input problems that map to exit code 2."""


def display(tool):
    return DISPLAY.get(tool, tool)


def norm_verdict(value):
    """Normalize a verdict string to pass|warn|fail, or None."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v in ("pass", "passed", "success", "ok"):
        return "pass"
    if v in ("warn", "warning", "warnings"):
        return "warn"
    if v in ("fail", "failed", "failure", "error"):
        return "fail"
    return None


def worst(verdicts):
    return max(verdicts, key=lambda v: VERDICT_RANK[v])


def make_result(tool, verdict, score, summary, source):
    """One normalized check result.

    `points` is what the composite actually averages: the native
    0-100 score when the tool reports one, otherwise the verdict
    mapping (pass 100 / warn 60 / fail 0).
    """
    points = float(score) if score is not None else VERDICT_POINTS[verdict]
    return {"tool": tool, "verdict": verdict,
            "score": None if score is None else round(float(score), 1),
            "points": points, "summary": summary, "source": source}


def _counts_phrase(counts, order=SEVERITIES):
    parts = [f"{counts[s]} {s}" for s in order if counts.get(s)]
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Adapters — one per sibling JSON shape, plus the generic trust-report.
# Each returns ("check", result) | ("info", note-dict) | None.
# A sibling's native verdict is mapped faithfully; where a tool has no
# verdict, the strongest derived verdict is WARN — TrustBadge never
# invents a failure the tool itself did not report.
# ---------------------------------------------------------------------------

def adapt_secretscan(data, source):
    """A bare list of findings: {file, line, check, type, severity}."""
    counts = {s: 0 for s in SEVERITIES}
    for f in data:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    total = len(data)
    if total == 0:
        return ("check", make_result(
            "secretscan", "pass", 100, "0 findings", source))
    penalty = sum(SEV_PENALTY[s] * n for s, n in counts.items())
    score = max(0, 100 - penalty)
    if counts["critical"] or counts["high"]:
        verdict = "fail"          # SecretScan's own default fail-on: high
    else:
        verdict = "warn"
    summary = f"{total} finding(s): {_counts_phrase(counts)}"
    return ("check", make_result("secretscan", verdict, score,
                                 summary, source))


def adapt_promptre(data, source):
    """A bare list of analyses, each with a structure_score."""
    scores = [a["structure_score"] for a in data
              if isinstance(a.get("structure_score"), (int, float))]
    if not scores:
        return None
    score = min(scores)           # the worst-analysed prompt governs
    # PromptRE reports no verdict; band its score (never a FAIL).
    verdict = "pass" if score >= 80 else "warn"
    summary = (f"structure score {score:g}/100"
               f" across {len(scores)} prompt(s) (worst governs)")
    return ("check", make_result("promptre", verdict, score,
                                 summary, source))


def adapt_agentproof(data, source):
    checks = data["checks"]
    if not checks:
        return ("check", make_result(
            "agentproof", "warn", None,
            "report contains no checks — nothing was verified", source))
    passed = sum(1 for c in checks if c.get("status") == "pass")
    failed = sum(1 for c in checks if c.get("status") == "fail")
    unknown = sum(1 for c in checks if c.get("status") == "unknown")
    if failed:
        verdict = "fail"
    elif unknown:
        verdict = "warn"
    else:
        verdict = "pass"
    score = round(100 * passed / len(checks))
    summary = f"{passed}/{len(checks)} checks passed"
    if failed:
        summary += f", {failed} failed"
    if unknown:
        summary += f", {unknown} unknown"
    return ("check", make_result("agentproof", verdict, score,
                                 summary, source))


def adapt_agentci_run(data, source):
    results = data["results"]
    total = len(results)
    if total == 0:
        return None
    passed = sum(1 for r in results if r.get("status") == "pass")
    failed = sum(1 for r in results if r.get("status") == "fail")
    missing = sum(1 for r in results if r.get("status") == "missing")
    # AgentCI's own rule: anything not passing fails the suite.
    verdict = "fail" if (failed or missing) else "pass"
    score = round(100 * passed / total)
    summary = f"{passed}/{total} cases passed"
    if failed:
        summary += f", {failed} failed"
    if missing:
        summary += f", {missing} missing"
    return ("check", make_result("agentci", verdict, score,
                                 summary, source))


def adapt_agentci_compare(data, source):
    regressions = data.get("regressions") or []
    improvements = data.get("improvements") or []
    verdict = "fail" if regressions else "pass"
    summary = (f"{len(regressions)} regression(s), "
               f"{len(improvements)} improvement(s) vs baseline")
    return ("check", make_result("agentci", verdict, None,
                                 summary, source))


def adapt_costledger_tally(data, source):
    totals = data.get("totals") or {}
    events = totals.get("events", data.get("events", 0))
    tokens = totals.get("total_tokens")
    problems = []
    if totals.get("cost_complete") is False:
        unknown = data.get("unknown_models") or []
        problems.append(
            "cost incomplete — unpriced model(s): "
            + (", ".join(map(str, unknown)) if unknown else "unknown"))
    if data.get("pricing_warnings"):
        problems.append(f"{len(data['pricing_warnings'])} pricing "
                        "warning(s)")
    if data.get("lines_malformed"):
        problems.append(f"{data['lines_malformed']} malformed line(s)")
    verdict = "warn" if problems else "pass"
    bits = [f"{events} event(s)"]
    if tokens is not None:
        bits.append(f"{tokens:,} tokens")
    cost = totals.get("cost_usd")
    if cost is not None:
        bits.append(f"total cost {cost}")
    summary = " · ".join(bits)
    if problems:
        summary += " — " + "; ".join(problems)
    return ("check", make_result("costledger", verdict, None,
                                 summary, source))


def adapt_costledger_compare(data, source):
    regressed = bool(data.get("regressed"))
    verdict = "fail" if regressed else "pass"
    pct = data.get("pct_change")
    summary = (f"cost {pct}% vs baseline "
               f"(threshold {data.get('threshold_pct')}%)")
    if regressed:
        summary += " — regression"
    return ("check", make_result("costledger", verdict, None,
                                 summary, source))


def adapt_schemaguard_validate(data, source):
    summary_d = data.get("summary") or {}
    total = summary_d.get("total", 0)
    passed = summary_d.get("passed", 0)
    failed = summary_d.get("failed", 0)
    warnings = data.get("warnings") or []
    if failed:
        verdict = "fail"
    elif warnings:
        verdict = "warn"
    else:
        verdict = "pass"
    score = summary_d.get("pass_rate")
    summary = f"{passed}/{total} outputs valid"
    if warnings:
        summary += f" · {len(warnings)} unsupported-keyword warning(s)"
    return ("check", make_result("schemaguard", verdict, score,
                                 summary, source))


def adapt_schemaguard_diff(data, source):
    breaking = data.get("breaking_count", 0)
    changes = data.get("changes") or []
    if breaking:
        verdict = "fail"
    elif changes:
        verdict = "warn"
    else:
        verdict = "pass"
    summary = (f"{breaking} breaking change(s), "
               f"{len(changes)} change(s) total")
    return ("check", make_result("schemaguard", verdict, None,
                                 summary, source))


def adapt_skillaudit(data, source):
    if isinstance(data.get("skills"), list):
        skills = data["skills"]
        if not skills:
            return None
        verdict = worst([norm_verdict(s.get("verdict")) or "pass"
                         for s in skills])
        summ = data.get("summary") or {}
        score = summ.get("worst_score",
                         min(s["score"] for s in skills
                             if isinstance(s.get("score"), (int, float))))
        summary = (f"{len(skills)} skill(s) audited · "
                   f"worst score {score:g}/100")
        return ("check", make_result("skillaudit", verdict, score,
                                     summary, source))
    verdict = norm_verdict(data.get("verdict"))
    if verdict is None:
        return None
    score = data.get("score")
    summary = (f"skill '{data.get('name', '?')}' · "
               f"{data.get('files_scanned', '?')} file(s) scanned · "
               f"{len(data.get('findings') or [])} finding(s)")
    return ("check", make_result("skillaudit", verdict, score,
                                 summary, source))


def adapt_claimcheck(data, source):
    verdict = norm_verdict(data.get("verdict"))
    if verdict is None:
        return None
    score = data.get("score")
    summ = data.get("summary") or {}
    if summ:
        summary = (f"{summ.get('claims', '?')} claim(s) · "
                   f"{summ.get('verified', 0)} verified · "
                   f"{summ.get('unbacked', 0)} unbacked · "
                   f"{summ.get('mismatch', 0)} mismatched")
    else:
        summary = f"{len(data.get('findings') or [])} finding(s)"
    return ("check", make_result("claimcheck", verdict, score,
                                 summary, source))


def adapt_promptlint(data, source):
    results = data["results"]
    if not results:
        return None
    verdict = worst([norm_verdict(r.get("verdict")) or "pass"
                     for r in results])
    summ = data.get("summary") or {}
    if isinstance(summ.get("worst_score"), (int, float)):
        score = summ["worst_score"]
    else:
        scores = [r["score"] for r in results
                  if isinstance(r.get("score"), (int, float))]
        score = min(scores) if scores else None
    findings = summ.get("findings",
                        sum(len(r.get("findings") or [])
                            for r in results))
    summary = (f"{len(results)} prompt(s) linted · "
               f"worst score {score:g}/100 · {findings} finding(s)")
    return ("check", make_result("promptlint", verdict, score,
                                 summary, source))


def adapt_promptdiff(data, source):
    if "old" in data and "new" in data:
        high = data.get("high_risks", 0)
        risks = data.get("risks") or []
        if high:
            verdict = "fail"
        elif risks:
            verdict = "warn"
        else:
            verdict = "pass"
        sim = data.get("similarity")
        sim_txt = (f"similarity {round(sim * 100)}%"
                   if isinstance(sim, (int, float)) else "similarity n/a")
        summary = (f"{sim_txt} · {high} high-risk change(s) · "
                   f"{len(risks)} risk(s) total")
        return ("check", make_result("promptdiff", verdict, None,
                                     summary, source))
    if "file" in data:
        return ("info", {"kind": "PromptDiff prompt profile "
                                 "(stats only — not a check)",
                         "source": source})
    return None


def adapt_tracetape(data, source):
    command = data.get("command")
    if command == "summary":
        return ("info", {"kind": "TraceTape run summary "
                                 "(not a validation)",
                         "source": source})
    if command != "validate" and "files" not in data:
        return None
    files = data.get("files") or []
    if not files:
        return None
    events = sum(f.get("events", 0) for f in files)
    errors = sum(len(f.get("errors") or []) for f in files)
    warns = sum(len(f.get("warnings") or []) for f in files)
    incomplete = sum(len(f.get("incomplete_runs") or []) for f in files)
    bad = any(not f.get("ok", False) for f in files) or incomplete > 0
    if bad:
        verdict = "fail"
    elif warns:
        verdict = "warn"
    else:
        verdict = "pass"
    summary = (f"{len(files)} tape(s) · {events} event(s) · "
               f"{errors} error(s) · {warns} warning(s)")
    if incomplete:
        summary += f" · {incomplete} incomplete run(s)"
    return ("check", make_result("tracetape", verdict, None,
                                 summary, source))


def adapt_generic(data, source):
    """The minimal trust-report shape any tool can emit:
    {"tool": ..., "verdict": pass|warn|fail,
     "score": 0-100|null, "summary": ...}"""
    tool = data.get("tool")
    verdict = norm_verdict(data.get("verdict"))
    if not isinstance(tool, str) or not tool or verdict is None:
        return None
    tool = tool.strip().lower()
    if tool == "trustbadge":
        return None                     # never aggregate ourselves
    score = data.get("score")
    if not isinstance(score, (int, float)):
        score = None
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary:
        summary = f"generic trust-report ({verdict})"
    return ("check", make_result(tool, verdict, score, summary, source))


def adapt_report(data, source):
    """Route one parsed JSON document to its adapter.

    Returns ("check", result) | ("info", note) | None (unrecognized).
    """
    if isinstance(data, list):
        if not data:
            # An empty findings list is a clean SecretScan report
            # (PromptRE never emits an empty analysis list).
            return adapt_secretscan(data, source)
        first = data[0]
        if isinstance(first, dict) and "structure_score" in first:
            return adapt_promptre(data, source)
        if isinstance(first, dict) and "severity" in first \
                and "check" in first:
            return adapt_secretscan(data, source)
        return None
    if not isinstance(data, dict):
        return None

    tool = data.get("tool")
    if tool == "skillaudit":
        return adapt_skillaudit(data, source)
    if tool == "claimcheck":
        return adapt_claimcheck(data, source)
    if tool == "promptlint" and isinstance(data.get("results"), list):
        return adapt_promptlint(data, source)
    if tool == "costledger" and isinstance(data.get("totals"), dict):
        return adapt_costledger_tally(data, source)
    if tool == "promptdiff":
        return adapt_promptdiff(data, source)
    if tool == "tracetape":
        return adapt_tracetape(data, source)

    # Shape-based adapters (these tools emit no top-level "tool",
    # or a shape shared across commands).
    if isinstance(data.get("checks"), list) and "repo" in data:
        return adapt_agentproof(data, source)
    if isinstance(data.get("results"), list) \
            and "summary" in data \
            and isinstance(data.get("summary"), dict) \
            and "pass_rate" in (data.get("summary") or {}):
        return adapt_schemaguard_validate(data, source)
    if "breaking_count" in data and "changes" in data:
        return adapt_schemaguard_diff(data, source)
    if isinstance(data.get("results"), list) and "cases_file" in data:
        return adapt_agentci_run(data, source)
    if "regressions" in data and "improvements" in data:
        return adapt_agentci_compare(data, source)
    if "regressed" in data and "baseline_total_usd" in data:
        return adapt_costledger_compare(data, source)

    return adapt_generic(data, source)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _round_half_up(x):
    return int(x + 0.5)


def aggregate_reports(reports_dir):
    """Read a reports directory and produce the aggregate report.

    Raises UsageError (exit 2) when there is nothing to aggregate.
    """
    base = Path(reports_dir)
    if not base.is_dir():
        raise UsageError(f"reports directory not found: {reports_dir}")
    files = sorted(base.glob("*.json"))
    if not files:
        raise UsageError(f"no .json reports in {reports_dir} — "
                         "nothing to aggregate")

    candidates = {}      # tool -> list of results (worst one counts)
    unrecognized = []
    unreadable = []
    informational = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            unreadable.append({"file": f.name, "error": str(e)})
            continue
        outcome = adapt_report(data, f.name)
        if outcome is None:
            unrecognized.append(f.name)
        elif outcome[0] == "info":
            informational.append(outcome[1])
        else:
            result = outcome[1]
            candidates.setdefault(result["tool"], []).append(result)

    if not candidates:
        raise UsageError(
            "no recognized check reports — nothing was scored "
            f"({len(unrecognized)} unrecognized, "
            f"{len(unreadable)} unreadable, "
            f"{len(informational)} informational)")

    checks = []
    for tool, results in candidates.items():
        # Several reports for one tool: the worst counts. A badge must
        # not hide a failing run behind a passing re-run.
        results.sort(key=lambda r: (r["points"], r["source"]))
        chosen = dict(results[0])
        if len(results) > 1:
            chosen["summary"] += f" (worst of {len(results)} reports)"
        chosen["family"] = tool in WEIGHTS
        chosen["weight"] = WEIGHTS.get(tool, EXTRA_WEIGHT)
        checks.append(chosen)

    def sort_key(c):
        return (-c["weight"], c["tool"])
    checks.sort(key=sort_key)

    total_weight = sum(c["weight"] for c in checks)
    raw = sum(c["weight"] * c["points"] for c in checks) / total_weight
    capped_by = [c["tool"] for c in checks if c["verdict"] == "fail"]
    capped = bool(capped_by)
    composite = _round_half_up(raw)
    if capped:
        composite = min(composite, FAIL_CAP)

    ran_family = sorted(t for t in candidates if t in WEIGHTS)
    missing = sorted(set(WEIGHTS) - set(ran_family))
    weights_table = {t: WEIGHTS[t] for t in sorted(WEIGHTS)}
    weights_table["(any other tool, generic trust-report)"] = EXTRA_WEIGHT

    return {
        "tool": "trustbadge",
        "version": VERSION,
        "reports_dir": str(reports_dir),
        "composite": composite,
        "raw_composite": round(raw, 1),
        "capped": capped,
        "capped_by": capped_by,
        "fail_cap": FAIL_CAP,
        "coverage": {"ran": len(ran_family), "total": len(WEIGHTS),
                     "missing": missing},
        "checks": checks,
        "unrecognized": unrecognized,
        "unreadable": unreadable,
        "informational": informational,
        "weights": weights_table,
    }


# ---------------------------------------------------------------------------
# Badge
# ---------------------------------------------------------------------------

BANDS = [(85, "#44cc11", "green"), (70, "#dfb317", "yellow"),
         (50, "#fe7d37", "orange"), (0, "#e05d44", "red")]


def badge_color(report):
    if report["capped"]:
        return "#e05d44"
    score = report["composite"]
    for threshold, color, _name in BANDS:
        if score >= threshold:
            return color
    return "#e05d44"


def _text_width(text):
    # Verdana at 11px: ~6.5px per character is the shields.io estimate.
    return int(len(text) * 6.5) + 10


def _xml_escape(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def badge_svg(report):
    label = "agent trust"
    value = (f"{report['composite']} · {report['coverage']['ran']}"
             f"/{report['coverage']['total']} checks")
    color = badge_color(report)
    left_w = _text_width(label)
    right_w = _text_width(value)
    total_w = left_w + right_w
    title = _xml_escape(f"agent trust: {value}")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" '
        f'height="20" role="img" aria-label="{title}">\n'
        f'  <title>{title}</title>\n'
        f'  <clipPath id="r"><rect width="{total_w}" height="20" '
        f'rx="3" fill="#fff"/></clipPath>\n'
        f'  <g clip-path="url(#r)">\n'
        f'    <rect width="{left_w}" height="20" fill="#555"/>\n'
        f'    <rect x="{left_w}" width="{right_w}" height="20" '
        f'fill="{color}"/>\n'
        f'  </g>\n'
        f'  <g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" '
        f'font-size="11">\n'
        f'    <text x="{left_w / 2:g}" y="14" '
        f'text-anchor="middle">{_xml_escape(label)}</text>\n'
        f'    <text x="{left_w + right_w / 2:g}" y="14" '
        f'text-anchor="middle">{_xml_escape(value)}</text>\n'
        f'  </g>\n'
        f'</svg>\n'
    )


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------

def print_text_report(report):
    cov = report["coverage"]
    print("=" * 68)
    print("TrustBadge — aggregate report")
    print("=" * 68)
    print(f"Reports: {report['reports_dir']}")
    print()
    print(f"  {'check':<14} {'verdict':<8} {'score':>6} {'weight':>6}  "
          "summary")
    for c in report["checks"]:
        score = ("—" if c["score"] is None else f"{c['score']:g}")
        print(f"  {display(c['tool']):<14} "
              f"{VERDICT_EMOJI[c['verdict']]} {c['verdict'].upper():<5} "
              f"{score:>6} {c['weight']:>6}  {c['summary']}")
    print()
    print(f"Composite: {report['composite']}/100 · "
          f"{cov['ran']} of {cov['total']} checks")
    if report["capped"]:
        names = ", ".join(display(t) for t in report["capped_by"])
        print(f"⚠️ Capped at {report['fail_cap']}: {names} FAILED — "
              f"raw weighted score was {report['raw_composite']:g}. "
              "A failed check caps the badge; fix the failure, "
              "not the arithmetic.")
    if cov["missing"]:
        names = ", ".join(display(t) for t in cov["missing"])
        print(f"Not run: {names} — missing checks never count "
              "as passes; they only narrow the coverage.")
    for note in report["informational"]:
        print(f"Not scored: {note['source']} — {note['kind']}.")
    for name in report["unrecognized"]:
        print(f"UNRECOGNIZED: {name} — not a known report shape; "
              "not scored.")
    for bad in report["unreadable"]:
        print(f"UNREADABLE: {bad['file']} — {bad['error']}; not scored.")


# ---------------------------------------------------------------------------
# init — scaffold sample reports (real sibling shapes, fictional data)
# ---------------------------------------------------------------------------

INIT_REPORTS = {
    "secretscan.json": [
        {"file": "agent-output.md", "line": 14,
         "check": "stripe-key", "type": "Stripe live secret key",
         "severity": "critical"},
        {"file": "agent-output.md", "line": 31,
         "check": "generic-api-key",
         "type": "Generic API key assignment", "severity": "medium"},
    ],
    "skillaudit.json": {
        "tool": "skillaudit", "version": "1.0.0",
        "skill": "sample-skill", "name": "sample-skill",
        "files_scanned": 3, "score": 98, "verdict": "PASS",
        "urls": ["https://example.org/docs"],
        "findings": [
            {"check": "external-url", "severity": "info",
             "category": "security", "path": "SKILL.md", "line": 12,
             "message": "External URL referenced: "
                        "https://example.org/docs", "snippet": ""},
        ],
    },
    "promptlint.json": {
        "tool": "promptlint", "version": "1.0.0",
        "results": [
            {"path": "prompt.md", "lines": 24, "findings": [
                {"check": "vague-term", "severity": "medium",
                 "category": "ambiguity", "line": 9,
                 "message": "Vague term 'as needed'.",
                 "snippet": ""},
                {"check": "vague-term", "severity": "medium",
                 "category": "ambiguity", "line": 15,
                 "message": "Vague term 'appropriate'.",
                 "snippet": ""},
            ], "counts": {"high": 0, "medium": 2, "low": 0, "info": 0},
             "score": 88, "verdict": "WARN"},
        ],
        "summary": {"files": 1, "failed": 0, "worst_score": 88,
                    "findings": 2},
    },
    "costledger.json": {
        "tool": "costledger", "version": 1,
        "generated_at": "2026-10-20T00:00:00+00:00",
        "sources": ["run.jsonl"],
        "pricing": {"as_of": "2026-10-20", "currency": "USD",
                    "source": "pricing.yaml"},
        "pricing_warnings": [], "events": 12, "events_skipped": 0,
        "lines_malformed": 0, "unknown_models": [],
        "totals": {"events": 12, "input_tokens": 9000,
                   "output_tokens": 3000, "total_tokens": 12000,
                   "cost_usd": "0.0420", "cost_complete": True},
        "by_model": {},
    },
}

INIT_EXPECTED = """\
# What to expect

`trustbadge aggregate reports` on this scaffold:

- **SecretScan — FAIL.** The sample findings list contains one
  critical (a Stripe-shaped key in an agent output) and one medium.
  SecretScan derives a score of 52 (100 − 40 critical − 8 medium)
  and FAILs, because its own fail-on threshold is `high`.
- **SkillAudit — PASS**, 98/100. **PromptLint — WARN**, 88/100.
  **CostLedger — PASS** (cost complete, no warnings).
- Raw weighted composite: (16·52 + 16·98 + 5·88 + 4·100) / 41
  = 79.0.
- **Composite shown: 49** — the FAIL cap. SecretScan failed, so the
  composite is capped at 49 no matter how well the rest scored.
  Coverage: 4 of 11 checks.

Fix the leak (delete `reports/secretscan.json` or replace it with
an empty findings list `[]`) and the cap lifts: the same folder
then scores 100 · 4 of 11 checks.
"""


def cmd_init(_args):
    reports_dir = Path("reports")
    expected = Path("EXPECTED.md")
    if expected.exists() or (reports_dir.exists()
                              and any(reports_dir.iterdir())):
        print("error: reports/ or EXPECTED.md already exists here — "
              "refusing to overwrite", file=sys.stderr)
        return 2
    reports_dir.mkdir(exist_ok=True)
    for name, payload in INIT_REPORTS.items():
        (reports_dir / name).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    expected.write_text(INIT_EXPECTED, encoding="utf-8")
    print(f"Scaffolded {len(INIT_REPORTS)} sample reports in reports/ "
          "+ EXPECTED.md")
    print("Run: trustbadge aggregate reports")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fail_under_exit(report, fail_under):
    if fail_under is not None and report["composite"] < fail_under:
        print(f"error: composite {report['composite']} is below "
              f"--fail-under {fail_under}", file=sys.stderr)
        return 1
    return 0


def cmd_aggregate(args):
    try:
        report = aggregate_reports(args.reports_dir)
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_text_report(report)
    return _fail_under_exit(report, args.fail_under)


def cmd_badge(args):
    try:
        report = aggregate_reports(args.reports_dir)
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.write_text(badge_svg(report), encoding="utf-8")
    print(f"![agent trust]({out.name})")
    print(f"Wrote {out} — composite {report['composite']}/100 · "
          f"{report['coverage']['ran']} of "
          f"{report['coverage']['total']} checks"
          + (" (capped: a check FAILED)" if report["capped"] else ""))
    return _fail_under_exit(report, args.fail_under)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="trustbadge",
        description="One badge. Every check behind it. Aggregate "
                    "AgentForge JSON reports into a single trust "
                    "score + README badge.")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("aggregate",
                       help="score a folder of JSON reports")
    a.add_argument("reports_dir")
    a.add_argument("--format", choices=("text", "json"),
                   default="text")
    a.add_argument("--fail-under", type=int, default=None,
                   help="exit 1 if the composite is below N")
    a.set_defaults(func=cmd_aggregate)

    b = sub.add_parser("badge",
                       help="write an SVG badge for a reports folder")
    b.add_argument("reports_dir")
    b.add_argument("--out", required=True, help="SVG file to write")
    b.add_argument("--fail-under", type=int, default=None,
                   help="exit 1 if the composite is below N")
    b.set_defaults(func=cmd_badge)

    i = sub.add_parser("init",
                       help="scaffold sample reports + EXPECTED.md")
    i.set_defaults(func=cmd_init)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
