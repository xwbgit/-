import json

from backend.app.evaluation.metrics import evaluate_findings


def test_metrics_are_computed_from_labels_and_predictions():
    truth = {
        "dataset_id": "synthetic",
        "version": "1",
        "positive_samples": [
            {"id": "a", "category": "VULN", "url_path": "/a", "title_regex": "SQL"},
            {"id": "b", "category": "TAMPER", "url_path": "/b", "title_regex": "篡改"},
            {"id": "c", "category": "SENSITIVE", "url_path": "/c", "title_regex": "身份证"},
        ],
        "negative_samples": [
            {"id": "n1", "category": "SENSITIVE", "url_path": "/safe", "title_regex": "身份证"},
            {"id": "n2", "category": "TAMPER", "url_path": "/safe", "title_regex": "暗链"},
        ],
    }
    findings = [
        {"id": "f1", "category": "VULN", "url": "https://test/a", "title": "SQL injection"},
        {"id": "f2", "category": "TAMPER", "url": "https://test/b", "title": "页面篡改"},
        {"id": "f3", "category": "SENSITIVE", "url": "https://test/safe", "title": "身份证"},
    ]
    result = evaluate_findings(findings, truth)
    assert result["overall"] == {
        "tp": 2,
        "fp": 1,
        "fn": 1,
        "tn": 1,
        "precision": 0.666667,
        "recall": 0.666667,
        "f1": 0.666667,
        "false_positive_rate": 0.5,
    }
    assert result["dataset_sha256"]
    assert result["missed_sample_ids"] == ["c"]


def test_metric_output_never_contains_source_sensitive_values():
    truth = {
        "dataset_id": "redaction-check",
        "positive_samples": [{"id": "secret", "category": "SENSITIVE", "title_regex": "Secret"}],
    }
    findings = [{
        "id": "finding-secret",
        "category": "SENSITIVE",
        "title": "Secret detected",
        "url": "https://example.test",
        "evidence": {"matched": "plain-text-secret"},
    }]
    result = evaluate_findings(findings, truth)
    assert "plain-text-secret" not in json.dumps(result)
