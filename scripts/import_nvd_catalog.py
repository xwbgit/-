import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _english_description(cve: Dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value") or "")
    return ""


def _cvss(cve: Dict[str, Any]) -> tuple[float, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        data = values[0].get("cvssData") or {}
        score = float(data.get("baseScore") or 0.0)
        severity = str(data.get("baseSeverity") or values[0].get("baseSeverity") or "MEDIUM").upper()
        return score, severity
    return 0.0, "MEDIUM"


def _walk_cpe_matches(node: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(node, dict):
        for match in node.get("cpeMatch") or []:
            if isinstance(match, dict):
                yield match
        for value in node.values():
            yield from _walk_cpe_matches(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_cpe_matches(value)


def import_nvd(payload: Dict[str, Any], source_label: str) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    seen = set()
    for wrapper in payload.get("vulnerabilities") or []:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("id") or "")
        if not cve_id:
            continue
        score, severity = _cvss(cve)
        references = [
            str(item.get("url"))
            for item in (cve.get("references") or [])
            if isinstance(item, dict) and item.get("url")
        ][:20]
        for match in _walk_cpe_matches(cve.get("configurations") or []):
            if match.get("vulnerable") is not True:
                continue
            criteria = str(match.get("criteria") or "")
            key = (cve_id, criteria, match.get("versionStartIncluding"), match.get("versionEndExcluding"))
            if not criteria or key in seen:
                continue
            seen.add(key)
            entry = {
                "cve_id": cve_id,
                "criteria": criteria,
                "severity": severity,
                "cvss_score": score,
                "description": _english_description(cve),
                "references": references,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
            }
            field_map = {
                "versionStartIncluding": "version_start_including",
                "versionStartExcluding": "version_start_excluding",
                "versionEndIncluding": "version_end_including",
                "versionEndExcluding": "version_end_excluding",
            }
            for source_key, target_key in field_map.items():
                if match.get(source_key) not in (None, ""):
                    entry[target_key] = match[source_key]
            entries.append(entry)
    return {
        "schema_version": "1.0",
        "source": source_label,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="将已下载的 NVD CVE API 2.0 JSON 转换为 DAS 本地版本目录")
    parser.add_argument("input", help="NVD JSON 输入文件")
    parser.add_argument("output", help="输出 cve_catalog.json")
    parser.add_argument("--source-label", default="NVD CVE API 2.0 offline export")
    args = parser.parse_args()
    source_path = Path(args.input)
    payload = json.loads(source_path.read_text(encoding="utf-8"))
    catalog = import_nvd(payload, args.source_label)
    Path(args.output).write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Imported {len(catalog['entries'])} vulnerable CPE records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
