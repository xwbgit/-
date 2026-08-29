import json

from plugins.scanner_extensions.vulnerability_intel.cve_matcher import CVEIntelMatcher


def test_missing_catalog_is_explicit(tmp_path):
    findings, summary = CVEIntelMatcher(tmp_path / "missing.json").match([
        "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"
    ])
    assert findings == []
    assert summary["status"] == "NOT_CONFIGURED"
    assert summary["match_count"] == 0


def test_catalog_matches_only_version_in_affected_range(tmp_path):
    catalog = {
        "schema_version": "1.0",
        "source": "synthetic test catalog",
        "updated_at": "2026-08-28T00:00:00Z",
        "entries": [{
            "cve_id": "CVE-TEST-0001",
            "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0.0",
            "version_end_excluding": "2.0.0",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "description": "Synthetic test record",
            "references": ["https://example.test/advisory"],
        }],
    }
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    matcher = CVEIntelMatcher(path)

    findings, summary = matcher.match([
        "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor:product:2.1.0:*:*:*:*:*:*:*",
    ])
    assert len(findings) == 1
    assert findings[0]["title"] == "[版本关联待复核] CVE-TEST-0001"
    assert findings[0]["verified"] == 0
    assert findings[0]["confidence_status"] == "SUSPECTED"
    assert summary["status"] == "MATCHED"
    assert summary["match_count"] == 1
