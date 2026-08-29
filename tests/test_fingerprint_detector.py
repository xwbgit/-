from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector


def _components(result):
    return [layer["component"] for layer in result["layers"]]


def test_unknown_stack_is_not_fabricated():
    result = ArchitectureFingerprintDetector.detect_architecture(
        "https://example.test",
        [{"url": "https://example.test", "headers": {}, "html_content": "<html><h1>Hello</h1></html>"}],
        [],
    )
    frontend, server, backend, database, security = _components(result)
    assert frontend["detected"] is False
    assert server["detected"] is False
    assert backend["detected"] is False
    assert database["detected"] is False
    assert "TLS 1.3" not in security["details"]
    assert result["cpe_candidates"] == []


def test_explicit_versions_create_traceable_cpe_candidates():
    result = ArchitectureFingerprintDetector.detect_architecture(
        "http://example.test",
        [{
            "url": "http://example.test",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
            "html_content": "<html></html>",
        }],
        [{"id": "finding-1", "evidence": {"matched_snippet": "SQL error from MySQL 8.0.32"}}],
    )
    _, server, backend, database, _ = _components(result)
    assert server["version"] == "2.4.41"
    assert backend["version"] == "7.4.3"
    assert database["version"] == "8.0.32"
    assert all(component["evidence"] for component in (server, backend, database))
    assert len(result["cpe_candidates"]) == 3
