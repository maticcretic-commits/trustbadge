"""Tests for TrustBadge adapters (every sibling JSON shape), the
aggregation math (weights, FAIL cap, coverage, worst-of-duplicates),
the badge SVG, --fail-under, and init scaffolding."""

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from trustbadge import (UsageError, adapt_report, aggregate_reports,
                        badge_color, badge_svg)

CLI = Path(__file__).parent.parent / "src" / "trustbadge.py"
EXAMPLES = Path(__file__).parent.parent / "examples"


def run_cli(*argv, cwd=None):
    return subprocess.run(
        [sys.executable, str(CLI), *argv],
        capture_output=True, text=True, cwd=cwd)


def write_reports(tmp_path, files):
    d = tmp_path / "reports"
    d.mkdir(exist_ok=True)
    for name, payload in files.items():
        text = payload if isinstance(payload, str) \
            else json.dumps(payload)
        (d / name).write_text(text, encoding="utf-8")
    return d


def check_of(data, source="x.json"):
    outcome = adapt_report(data, source)
    assert outcome is not None and outcome[0] == "check"
    return outcome[1]


# ---------------------------------------------------------------------------
# Adapter: SecretScan (bare findings list)
# ---------------------------------------------------------------------------

def finding(sev):
    return {"file": "out.md", "line": 1, "check": "x", "type": "X",
            "severity": sev}


def test_secretscan_clean_list_passes():
    r = check_of([])
    assert r["tool"] == "secretscan"
    assert r["verdict"] == "pass" and r["score"] == 100


def test_secretscan_critical_fails_with_penalty_score():
    r = check_of([finding("critical"), finding("medium")])
    assert r["verdict"] == "fail"
    assert r["score"] == 52          # 100 - 40 - 8
    assert "1 critical" in r["summary"]


def test_secretscan_medium_only_warns():
    r = check_of([finding("medium")])
    assert r["verdict"] == "warn" and r["score"] == 92


def test_secretscan_high_fails_like_the_tool():
    r = check_of([finding("high")])
    assert r["verdict"] == "fail"    # its own fail-on default is high


# ---------------------------------------------------------------------------
# Adapter: PromptRE (bare analysis list, structure_score)
# ---------------------------------------------------------------------------

def test_promptre_bands_and_worst_governs():
    r = check_of([{"file": "a.md", "structure_score": 95},
                  {"file": "b.md", "structure_score": 65}])
    assert r["tool"] == "promptre"
    assert r["score"] == 65 and r["verdict"] == "warn"


def test_promptre_high_score_passes():
    r = check_of([{"file": "a.md", "structure_score": 92}])
    assert r["verdict"] == "pass" and r["points"] == 92


# ---------------------------------------------------------------------------
# Adapters: AgentProof / AgentCI
# ---------------------------------------------------------------------------

def proof(statuses):
    return {"repo": "r", "branch": "main", "commit": "abc",
            "timestamp": "t",
            "checks": [{"name": f"c{i}", "status": s, "detail": "",
                        "duration_ms": 0}
                       for i, s in enumerate(statuses)]}


def test_agentproof_fail_and_score():
    r = check_of(proof(["pass", "pass", "pass", "fail"]))
    assert r["verdict"] == "fail" and r["score"] == 75


def test_agentproof_unknown_warns():
    r = check_of(proof(["pass", "unknown"]))
    assert r["verdict"] == "warn" and r["score"] == 50


def test_agentci_run_missing_fails():
    data = {"agent": "a", "timestamp": "t", "cases_file": "c.json",
            "outputs_file": "o.json",
            "results": [{"id": "1", "status": "pass", "checks": []},
                        {"id": "2", "status": "missing", "checks": [],
                         "reason": "no output"}]}
    r = check_of(data)
    assert r["tool"] == "agentci" and r["verdict"] == "fail"
    assert r["score"] == 50


def test_agentci_compare_regressions():
    r = check_of({"baseline": "b", "regressions": [{"id": "x"}],
                  "improvements": [], "unchanged": []})
    assert r["verdict"] == "fail" and r["score"] is None
    r2 = check_of({"regressions": [], "improvements": [{"id": "y"}]})
    assert r2["verdict"] == "pass"


# ---------------------------------------------------------------------------
# Adapters: CostLedger (tally + compare)
# ---------------------------------------------------------------------------

def tally(cost_complete=True, unknown=(), warnings=(), malformed=0):
    return {"tool": "costledger", "version": 1, "events": 5,
            "events_skipped": 0, "lines_malformed": malformed,
            "pricing_warnings": list(warnings),
            "unknown_models": list(unknown),
            "totals": {"events": 5, "input_tokens": 100,
                       "output_tokens": 50, "total_tokens": 150,
                       "cost_usd": "0.01" if cost_complete else None,
                       "cost_complete": cost_complete}}


def test_costledger_tally_incomplete_warns_and_names_model():
    r = check_of(tally(cost_complete=False, unknown=["mystery-1"]))
    assert r["verdict"] == "warn" and r["score"] is None
    assert "mystery-1" in r["summary"]


def test_costledger_tally_complete_passes():
    r = check_of(tally())
    assert r["verdict"] == "pass" and r["points"] == 100


def test_costledger_compare_regressed_fails():
    r = check_of({"baseline_total_usd": "1.0", "new_total_usd": "1.5",
                  "diff_usd": "0.5", "pct_change": "50",
                  "threshold_pct": "10", "regressed": True,
                  "by_model": [], "by_tool": []})
    assert r["tool"] == "costledger" and r["verdict"] == "fail"


# ---------------------------------------------------------------------------
# Adapters: SchemaGuard (validate + diff)
# ---------------------------------------------------------------------------

def sg_validate(passed=3, total=3, warnings=()):
    failed = total - passed
    return {"schema": "s.json", "strict": False,
            "results": [{"source": "a.json", "status": "pass",
                         "errors": []}] * total,
            "summary": {"total": total, "passed": passed,
                        "failed": failed,
                        "pass_rate": round(100 * passed / total, 1)
                        if total else 100.0},
            "warnings": list(warnings)}


def test_schemaguard_validate_fail_uses_pass_rate():
    r = check_of(sg_validate(passed=2, total=3))
    assert r["verdict"] == "fail" and r["score"] == 66.7
    assert r["points"] == pytest.approx(66.7)


def test_schemaguard_validate_warnings_warn():
    r = check_of(sg_validate(warnings=["$ref unsupported"]))
    assert r["verdict"] == "warn"


def test_schemaguard_diff_breaking_warn_and_clean():
    r = check_of({"old": "a", "new": "b", "breaking_count": 2,
                  "changes": [{"path": "$.x", "breaking": True}]})
    assert r["verdict"] == "fail"
    r = check_of({"old": "a", "new": "b", "breaking_count": 0,
                  "changes": [{"path": "$.y", "breaking": False}]})
    assert r["verdict"] == "warn"
    r = check_of({"old": "a", "new": "b", "breaking_count": 0,
                  "changes": []})
    assert r["verdict"] == "pass"


# ---------------------------------------------------------------------------
# Adapters: SkillAudit / ClaimCheck / PromptLint (native verdict+score)
# ---------------------------------------------------------------------------

def test_skillaudit_single_native():
    r = check_of({"tool": "skillaudit", "version": "1.0.0",
                  "skill": "s", "name": "s", "files_scanned": 2,
                  "score": 98, "verdict": "PASS", "findings": []})
    assert r["verdict"] == "pass" and r["score"] == 98


def test_skillaudit_audit_all_worst_governs():
    data = {"tool": "skillaudit", "version": "1.0.0", "root": "x",
            "skills": [
                {"name": "good", "score": 100, "verdict": "PASS",
                 "findings": []},
                {"name": "bad", "score": 0, "verdict": "FAIL",
                 "findings": []}],
            "summary": {"audited": 2, "failed": 1, "worst_score": 0}}
    r = check_of(data)
    assert r["verdict"] == "fail" and r["score"] == 0


def test_claimcheck_native():
    r = check_of({"tool": "claimcheck", "version": "1.0.0",
                  "score": 88, "verdict": "WARN",
                  "summary": {"claims": 6, "verified": 5,
                              "backed": 1, "unbacked": 0,
                              "mismatch": 0, "unverifiable": 0},
                  "findings": []})
    assert r["verdict"] == "warn" and r["score"] == 88
    assert "5 verified" in r["summary"]


def test_promptlint_worst_result_governs():
    data = {"tool": "promptlint", "version": "1.0.0",
            "results": [
                {"path": "a.md", "score": 96, "verdict": "PASS",
                 "findings": []},
                {"path": "b.md", "score": 9, "verdict": "FAIL",
                 "findings": [{"check": "x"}]}],
            "summary": {"files": 2, "failed": 1, "worst_score": 9,
                        "findings": 1}}
    r = check_of(data)
    assert r["verdict"] == "fail" and r["score"] == 9


# ---------------------------------------------------------------------------
# Adapters: PromptDiff / TraceTape
# ---------------------------------------------------------------------------

def test_promptdiff_high_risk_fails():
    r = check_of({"tool": "promptdiff", "version": "1.0.0",
                  "old": "a.md", "new": "b.md", "identical": False,
                  "similarity": 0.43, "risks": [{}, {}],
                  "high_risks": 2})
    assert r["verdict"] == "fail"
    r = check_of({"tool": "promptdiff", "old": "a", "new": "b",
                  "identical": True, "similarity": 1.0, "risks": [],
                  "high_risks": 0})
    assert r["verdict"] == "pass"


def test_promptdiff_stats_is_informational():
    outcome = adapt_report({"tool": "promptdiff", "version": "1.0.0",
                            "file": "p.md", "chars": 10}, "stats.json")
    assert outcome[0] == "info"


def tape_file(ok=True, errors=(), warnings=(), incomplete=()):
    return {"file": "t.jsonl", "events": 10, "lines": 10,
            "runs": ["r1"], "incomplete_runs": list(incomplete),
            "errors": list(errors), "warnings": list(warnings),
            "ok": ok, "blank_lines": 0}


def test_tracetape_validate_pass_warn_fail():
    base = {"tool": "tracetape", "version": "1.0.0",
            "command": "validate"}
    r = check_of({**base, "ok": True, "files": [tape_file()]})
    assert r["verdict"] == "pass"
    r = check_of({**base, "ok": True,
                  "files": [tape_file(warnings=[{"line": 1}])]})
    assert r["verdict"] == "warn"
    r = check_of({**base, "ok": False,
                  "files": [tape_file(ok=False, incomplete=["r1"])]})
    assert r["verdict"] == "fail"
    assert "incomplete" in r["summary"]


def test_tracetape_summary_is_informational(tmp_path):
    d = write_reports(tmp_path, {
        "secretscan.json": [],
        "summary.json": {"tool": "tracetape", "command": "summary",
                         "file": "t.jsonl", "runs": []}})
    report = aggregate_reports(d)
    assert report["coverage"]["ran"] == 1
    assert len(report["informational"]) == 1


# ---------------------------------------------------------------------------
# Generic trust-report shape + unrecognized input
# ---------------------------------------------------------------------------

def test_generic_fills_family_slot():
    r = check_of({"tool": "SecretScan", "verdict": "Pass",
                  "score": 73, "summary": "ran fine"})
    assert r["tool"] == "secretscan" and r["points"] == 73


def test_generic_extra_tool_and_null_score():
    r = check_of({"tool": "my-linter", "verdict": "WARN",
                  "score": None})
    assert r["tool"] == "my-linter" and r["points"] == 60


def test_generic_fail_case_insensitive():
    r = check_of({"tool": "x-tool", "verdict": "FAIL", "score": 90})
    assert r["verdict"] == "fail"


def test_unrecognized_shapes_return_none():
    assert adapt_report({"hello": "world"}, "m.json") is None
    assert adapt_report(42, "n.json") is None
    assert adapt_report([{"random": 1}], "r.json") is None


def test_own_output_is_unrecognized():
    assert adapt_report({"tool": "trustbadge", "verdict": "pass",
                         "score": 90}, "tb.json") is None


# ---------------------------------------------------------------------------
# Aggregation math
# ---------------------------------------------------------------------------

def test_weight_math_is_exact(tmp_path):
    d = write_reports(tmp_path, {
        "a.json": {"tool": "secretscan", "verdict": "pass",
                   "score": 80},
        "b.json": {"tool": "agentci", "verdict": "warn",
                   "score": None}})
    report = aggregate_reports(d)
    # (16*80 + 10*60) / 26 = 72.307... -> 72
    assert report["composite"] == 72
    assert report["capped"] is False
    assert report["coverage"] == {
        "ran": 2, "total": 11,
        "missing": sorted(set(
            ["agentproof", "claimcheck", "costledger", "promptdiff",
             "promptlint", "promptre", "schemaguard", "skillaudit",
             "tracetape"]))}


def test_fail_cap_overrides_high_raw(tmp_path):
    d = write_reports(tmp_path, {
        "a.json": {"tool": "skillaudit", "verdict": "pass",
                   "score": 100},
        "b.json": {"tool": "promptlint", "verdict": "pass",
                   "score": 100},
        "c.json": {"tool": "secretscan", "verdict": "fail",
                   "score": 95}})
    report = aggregate_reports(d)
    assert report["raw_composite"] > 90
    assert report["composite"] == 49
    assert report["capped"] is True
    assert report["capped_by"] == ["secretscan"]


def test_extra_tool_weighted_but_not_coverage(tmp_path):
    d = write_reports(tmp_path, {
        "a.json": {"tool": "secretscan", "verdict": "pass",
                   "score": 100},
        "b.json": {"tool": "other-tool", "verdict": "pass",
                   "score": 0}})
    report = aggregate_reports(d)
    assert report["coverage"]["ran"] == 1
    extra = [c for c in report["checks"]
             if c["tool"] == "other-tool"][0]
    assert extra["weight"] == 5 and extra["family"] is False
    # (16*100 + 5*0) / 21 = 76.19 -> 76
    assert report["composite"] == 76


def test_duplicate_tool_worst_wins(tmp_path):
    d = write_reports(tmp_path, {
        "scan-good.json": [],
        "scan-bad.json": [finding("critical")]})
    report = aggregate_reports(d)
    assert report["coverage"]["ran"] == 1
    only = report["checks"][0]
    assert only["tool"] == "secretscan" and only["verdict"] == "fail"
    assert "worst of 2 reports" in only["summary"]


def test_unrecognized_and_unreadable_listed(tmp_path):
    d = write_reports(tmp_path, {
        "good.json": [],
        "mystery.json": {"hello": "world"},
        "broken.json": "{not json"})
    report = aggregate_reports(d)
    assert report["unrecognized"] == ["mystery.json"]
    assert [u["file"] for u in report["unreadable"]] == ["broken.json"]
    assert report["composite"] == 100


def test_empty_and_unrecognized_only_raise(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(UsageError):
        aggregate_reports(empty)
    d = write_reports(tmp_path, {"mystery.json": {"hello": "world"}})
    with pytest.raises(UsageError):
        aggregate_reports(d)
    with pytest.raises(UsageError):
        aggregate_reports(tmp_path / "does-not-exist")


def test_json_output_shape(tmp_path):
    d = write_reports(tmp_path, {"a.json": []})
    out = run_cli("aggregate", str(d), "--format", "json")
    assert out.returncode == 0
    report = json.loads(out.stdout)
    for key in ("composite", "capped", "coverage", "checks",
                "weights", "unrecognized"):
        assert key in report
    assert report["weights"]["secretscan"] == 16
    assert report["checks"][0]["weight"] == 16


def test_fail_under_exit_codes(tmp_path):
    d = write_reports(tmp_path, {
        "a.json": {"tool": "agentci", "verdict": "warn",
                   "score": None}})
    assert run_cli("aggregate", str(d)).returncode == 0
    assert run_cli("aggregate", str(d),
                   "--fail-under", "80").returncode == 1
    assert run_cli("aggregate", str(d),
                   "--fail-under", "50").returncode == 0


def test_cli_empty_dir_exit_2(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    out = run_cli("aggregate", str(empty))
    assert out.returncode == 2


# ---------------------------------------------------------------------------
# Badge
# ---------------------------------------------------------------------------

def fake_report(composite, capped=False, ran=7, total=11):
    return {"composite": composite, "capped": capped,
            "coverage": {"ran": ran, "total": total, "missing": []}}


def test_badge_svg_is_valid_xml_with_text():
    svg = badge_svg(fake_report(82))
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "agent trust" in svg
    assert "82 · 7/11 checks" in svg


def test_badge_color_bands():
    assert badge_color(fake_report(95)) == "#44cc11"
    assert badge_color(fake_report(85)) == "#44cc11"
    assert badge_color(fake_report(70)) == "#dfb317"
    assert badge_color(fake_report(50)) == "#fe7d37"
    assert badge_color(fake_report(49)) == "#e05d44"
    assert badge_color(fake_report(0)) == "#e05d44"


def test_badge_capped_is_red_regardless():
    assert badge_color(fake_report(90, capped=True)) == "#e05d44"
    assert 'fill="#e05d44"' in badge_svg(fake_report(90, capped=True))


def test_badge_cli_writes_file_and_snippet(tmp_path):
    d = write_reports(tmp_path, {"a.json": []})
    out_path = tmp_path / "badge.svg"
    out = run_cli("badge", str(d), "--out", str(out_path))
    assert out.returncode == 0
    assert "![agent trust](badge.svg)" in out.stdout
    ET.parse(out_path)


# ---------------------------------------------------------------------------
# init scaffolding
# ---------------------------------------------------------------------------

def test_init_scaffold_cap_fires(tmp_path):
    out = run_cli("init", cwd=tmp_path)
    assert out.returncode == 0
    assert (tmp_path / "EXPECTED.md").exists()
    assert len(list((tmp_path / "reports").glob("*.json"))) == 4
    report = aggregate_reports(tmp_path / "reports")
    assert report["composite"] == 49 and report["capped"] is True
    assert report["raw_composite"] == pytest.approx(79.0)
    assert report["coverage"]["ran"] == 4


def test_init_refuses_overwrite(tmp_path):
    assert run_cli("init", cwd=tmp_path).returncode == 0
    assert run_cli("init", cwd=tmp_path).returncode == 2


# ---------------------------------------------------------------------------
# Shipped examples behave as the README says
# ---------------------------------------------------------------------------

def test_examples_reports_capped_at_49():
    report = aggregate_reports(EXAMPLES / "reports")
    assert report["coverage"]["ran"] == 8
    assert report["capped"] is True
    assert report["composite"] == 49


def test_examples_badge_matches_reports():
    svg = (EXAMPLES / "badge.svg").read_text(encoding="utf-8")
    ET.fromstring(svg)
    assert "49 · 8/11 checks" in svg


def test_reports_real_dogfood():
    report = aggregate_reports(EXAMPLES / "reports-real")
    assert report["coverage"]["ran"] == 3
    tools = {c["tool"] for c in report["checks"]}
    assert tools == {"secretscan", "promptlint", "tracetape"}


# ---------------------------------------------------------------------------
# Envelope shapes (Phase 1: tool/version/schema_version + fast paths)
# ---------------------------------------------------------------------------

def secretscan_envelope(findings):
    return {"tool": "secretscan", "version": "1.0.0",
            "schema_version": 1,
            "findings_summary": {
                "count": len(findings),
                "highest_severity":
                    "HIGH" if findings else "NONE"},
            "findings": findings}


def test_secretscan_envelope_high_finding_fails(tmp_path):
    d = write_reports(tmp_path, {
        "secretscan.json": secretscan_envelope([finding("high")])})
    report = aggregate_reports(d)
    checks = [c for c in report["checks"] if c["tool"] == "secretscan"]
    assert len(checks) == 1 and checks[0]["verdict"] == "fail"


def test_secretscan_envelope_empty_findings_passes(tmp_path):
    d = write_reports(tmp_path, {
        "secretscan.json": secretscan_envelope([])})
    report = aggregate_reports(d)
    checks = [c for c in report["checks"] if c["tool"] == "secretscan"]
    assert len(checks) == 1 and checks[0]["verdict"] == "pass"


def test_promptre_envelope_worst_score_governs(tmp_path):
    d = write_reports(tmp_path, {
        "promptre.json": {
            "tool": "promptre", "version": "1.0.0",
            "schema_version": 1,
            "results": [{"file": "a.md", "structure_score": 95},
                        {"file": "b.md", "structure_score": 65}]}})
    report = aggregate_reports(d)
    checks = [c for c in report["checks"] if c["tool"] == "promptre"]
    assert len(checks) == 1 and checks[0]["score"] == 65


def test_envelope_findings_summary_generic_fail():
    r = check_of({"tool": "sometool", "version": "9.9",
                  "schema_version": 1,
                  "findings_summary": {"count": 2,
                                       "highest_severity": "HIGH"}})
    assert r["tool"] == "sometool" and r["verdict"] == "fail"
    assert r["score"] is None


def test_envelope_findings_summary_generic_pass():
    r = check_of({"tool": "sometool", "version": "9.9",
                  "schema_version": 1,
                  "findings_summary": {"count": 0,
                                       "highest_severity": "NONE"}})
    assert r["verdict"] == "pass" and r["score"] is None


def test_trustbadge_envelope_still_refused():
    assert adapt_report(
        {"tool": "trustbadge", "version": "1.0.0",
         "schema_version": 1,
         "findings_summary": {"count": 3,
                              "highest_severity": "HIGH"}},
        "tb.json") is None


def test_aggregate_json_has_schema_version(tmp_path):
    d = write_reports(tmp_path, {"a.json": []})
    out = run_cli("aggregate", str(d), "--format", "json")
    assert out.returncode == 0
    report = json.loads(out.stdout)
    assert report["schema_version"] == 1
    assert isinstance(report["schema_version"], int)


def test_version_flag():
    out = run_cli("--version")
    assert out.returncode == 0
    assert out.stdout.strip() == "trustbadge 1.0.0"


def test_dogfood_real_secretscan_envelope(tmp_path):
    sibling = (Path(__file__).parent.parent.parent / "secretscan"
               / "src" / "secretscan.py")
    if not sibling.exists():
        pytest.skip("sibling secretscan not available")
    planted = tmp_path / "planted.txt"
    planted.write_text("key = " + "AKIA" + "IOSFODNN7" + "EXAMPLE"
                       + "\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(sibling), "scan", str(planted),
         "--format", "json"],
        capture_output=True, text=True)
    # A high finding exits 1 in SecretScan; the JSON is what matters.
    payload = json.loads(proc.stdout)
    assert payload["tool"] == "secretscan"
    assert payload["schema_version"] == 1
    assert isinstance(payload["findings"], list) \
        and len(payload["findings"]) == 1
    d = write_reports(tmp_path, {"secretscan.json": payload})
    report = aggregate_reports(d)
    checks = [c for c in report["checks"] if c["tool"] == "secretscan"]
    assert len(checks) == 1 and checks[0]["verdict"] == "fail"
