import json

import pytest

from plugins.core.base import ScanContext
from plugins.scanner_extensions.tool_adapters.adapters import (
    GitleaksAdapter,
    NucleiAdapter,
    ZapBaselineAdapter,
)
from plugins.scanner_extensions.tool_adapters.base import ToolExecutionError
from plugins.scanner_extensions.tool_adapters.scanner import OpenSourceToolScanner


def test_external_tools_require_explicit_authorization():
    context = ScanContext(task_id="t1", target_url="https://example.test", auth_domains=[])
    with pytest.raises(ToolExecutionError, match="授权域名"):
        NucleiAdapter.assert_authorized(context)


@pytest.mark.anyio
async def test_missing_tool_binaries_are_recorded_as_skipped(monkeypatch):
    from backend.app.config import settings

    monkeypatch.setattr(settings, "EXTERNAL_TOOL_ALLOWLIST", "nuclei,gitleaks,zap")
    monkeypatch.setattr(NucleiAdapter, "find_executable", lambda self: None)
    monkeypatch.setattr(GitleaksAdapter, "find_executable", lambda self: None)
    monkeypatch.setattr(ZapBaselineAdapter, "find_executable", lambda self: None)
    context = ScanContext(
        task_id="t2",
        target_url="https://example.test",
        auth_domains=["example.test"],
        scan_scope={"enable_vuln_check": True, "enable_sensitive_check": True},
    )
    await OpenSourceToolScanner().run(context)
    assert [item["status"] for item in context.metadata["tool_runs"]] == ["SKIPPED"] * 3
    assert context.findings == []


def test_nuclei_jsonl_is_normalized_without_query_secrets():
    payload = {
        "template-id": "missing-csp",
        "info": {"name": "Missing CSP", "severity": "medium"},
        "matched-at": "https://example.test/page?token=plain-secret",
        "matcher-name": "header",
        "matcher-status": True,
    }
    findings = NucleiAdapter.parse_findings(json.dumps(payload), "v3-test")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["url"] == "https://example.test/page"
    assert finding["verified"] == 1
    assert finding["evidence"]["tool_version"] == "v3-test"
    assert "plain-secret" not in json.dumps(finding)


def test_gitleaks_json_is_redacted_and_mapped_back_to_url():
    payload = [{
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "abc.html",
        "StartLine": 8,
        "Secret": "do-not-persist",
        "Match": "token=do-not-persist",
        "Fingerprint": "abc:generic-api-key:8",
    }]
    findings = GitleaksAdapter.parse_findings(
        json.dumps(payload),
        {"abc.html": "https://example.test/config"},
        "8-test",
    )
    serialized = json.dumps(findings)
    assert len(findings) == 1
    assert findings[0]["url"] == "https://example.test/config"
    assert findings[0]["evidence"]["secret_redacted"] is True
    assert "do-not-persist" not in serialized


def test_zap_report_is_normalized_and_masks_header_tokens():
    report = {
        "site": [{
            "@name": "https://example.test",
            "alerts": [{
                "pluginid": "10020",
                "alert": "X-Frame-Options Header Not Set",
                "riskcode": "2",
                "desc": "Header is missing",
                "solution": "Set the header",
                "instances": [{
                    "uri": "https://example.test/",
                    "method": "GET",
                    "evidence": "Authorization: Bearer abc.def.secret",
                }],
            }],
        }],
    }
    findings = ZapBaselineAdapter.parse_findings(json.dumps(report), "baseline-test")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    serialized = json.dumps(findings)
    assert "abc.def.secret" not in serialized
    assert "REDACTED" in serialized
