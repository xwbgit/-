import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse


def _safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 6) if denominator else None


def _sample_matches(sample: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    category = sample.get("category")
    if category and str(finding.get("category") or "").upper() != str(category).upper():
        return False

    checks = [
        (sample.get("title_regex"), str(finding.get("title") or "")),
        (sample.get("url_regex"), str(finding.get("url") or "")),
        (sample.get("param_regex"), str(finding.get("param") or "")),
        (sample.get("evidence_regex"), json.dumps(finding.get("evidence") or {}, ensure_ascii=False, sort_keys=True)),
    ]
    for pattern, value in checks:
        if pattern and not re.search(str(pattern), value, re.I):
            return False

    expected_path = sample.get("url_path")
    if expected_path is not None and urlparse(str(finding.get("url") or "")).path != expected_path:
        return False
    return True


def _metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, Any]:
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = round(2 * precision * recall / (precision + recall), 6)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _safe_ratio(fp, fp + tn),
    }


def evaluate_findings(
    findings: Iterable[Dict[str, Any]],
    ground_truth: Dict[str, Any],
    *,
    _include_category_metrics: bool = True,
) -> Dict[str, Any]:
    predictions = [dict(finding) for finding in findings]
    positives = list(ground_truth.get("positive_samples") or [])
    negatives = list(ground_truth.get("negative_samples") or [])
    used_predictions = set()
    matched_samples: List[Dict[str, Any]] = []
    missed_samples: List[Dict[str, Any]] = []

    for sample in positives:
        matched_index = next(
            (
                index
                for index, finding in enumerate(predictions)
                if index not in used_predictions and _sample_matches(sample, finding)
            ),
            None,
        )
        if matched_index is None:
            missed_samples.append(sample)
            continue
        used_predictions.add(matched_index)
        matched_samples.append({
            "sample_id": sample.get("id"),
            "finding_id": predictions[matched_index].get("id"),
        })

    negative_violations: List[Dict[str, Any]] = []
    true_negatives = 0
    for sample in negatives:
        matching = [
            index
            for index, finding in enumerate(predictions)
            if index not in used_predictions and _sample_matches(sample, finding)
        ]
        if not matching:
            true_negatives += 1
            continue
        for index in matching:
            used_predictions.add(index)
        negative_violations.append({
            "sample_id": sample.get("id"),
            "finding_ids": [predictions[index].get("id") for index in matching],
        })

    unmatched_indexes = [index for index in range(len(predictions)) if index not in used_predictions]
    false_positive_count = sum(len(item["finding_ids"]) for item in negative_violations) + len(unmatched_indexes)
    overall = _metrics(
        tp=len(matched_samples),
        fp=false_positive_count,
        fn=len(missed_samples),
        tn=true_negatives,
    )

    category_metrics: Dict[str, Any] = {}
    if _include_category_metrics:
        categories = sorted({
            str(item.get("category") or "UNSPECIFIED").upper()
            for item in positives + negatives + predictions
        })
        for category in categories:
            category_truth = {
                "positive_samples": [item for item in positives if str(item.get("category") or "UNSPECIFIED").upper() == category],
                "negative_samples": [item for item in negatives if str(item.get("category") or "UNSPECIFIED").upper() == category],
            }
            category_predictions = [
                finding
                for finding in predictions
                if str(finding.get("category") or "UNSPECIFIED").upper() == category
            ]
            if category_truth["positive_samples"] or category_truth["negative_samples"]:
                category_result = evaluate_findings(
                    category_predictions,
                    {**category_truth, "dataset_id": category},
                    _include_category_metrics=False,
                )
                category_metrics[category] = category_result["overall"]

    serialized_truth = json.dumps(ground_truth, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "dataset_id": ground_truth.get("dataset_id") or "unspecified",
        "dataset_version": ground_truth.get("version") or "unspecified",
        "dataset_sha256": hashlib.sha256(serialized_truth.encode("utf-8")).hexdigest(),
        "prediction_count": len(predictions),
        "positive_sample_count": len(positives),
        "negative_sample_count": len(negatives),
        "overall": overall,
        "by_category": category_metrics,
        "matched_samples": matched_samples,
        "missed_sample_ids": [item.get("id") for item in missed_samples],
        "negative_violations": negative_violations,
        "unmatched_finding_ids": [predictions[index].get("id") for index in unmatched_indexes],
    }


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))
