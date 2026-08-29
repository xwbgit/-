import argparse
import json
from pathlib import Path

from backend.app.evaluation.metrics import evaluate_findings, load_json


def main() -> int:
    parser = argparse.ArgumentParser(description="根据标注集计算巡检结果的 Precision/Recall/F1/FPR")
    parser.add_argument("findings", help="包含 findings 数组的 JSON 文件，或直接的 JSON 数组")
    parser.add_argument("ground_truth", help="标注集 JSON 文件")
    parser.add_argument("--output", help="可选的指标 JSON 输出路径")
    args = parser.parse_args()

    payload = load_json(args.findings)
    findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        parser.error("findings 输入必须是数组，或包含 findings 数组的对象")
    result = evaluate_findings(findings, load_json(args.ground_truth))
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
