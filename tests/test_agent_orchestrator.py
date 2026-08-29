import asyncio
import json
import os
import threading
import time
from pathlib import Path
import pytest

if os.getenv("RUN_LAB_INTEGRATION") != "1":
    pytest.skip("本地靶场集成测试需显式设置 RUN_LAB_INTEGRATION=1", allow_module_level=True)

import uvicorn
from backend.app.database import init_db, get_db_connection
from backend.app.config import settings
from backend.app.models.task import TaskCreateRequest
from backend.app.agent.orchestrator import InspectionOrchestrator
from backend.app.evaluation.metrics import evaluate_findings
from target_lab.lab_server import lab_app

@pytest.fixture(scope="session", autouse=True)
def run_lab_server(tmp_path_factory):
    temp_root = tmp_path_factory.mktemp("pipeline")
    old_database_path = settings.DATABASE_PATH
    old_reports_dir = settings.REPORTS_DIR
    old_external_tools = settings.ENABLE_EXTERNAL_TOOLS
    settings.DATABASE_PATH = str(temp_root / "pipeline.db")
    settings.REPORTS_DIR = str(temp_root / "reports")
    settings.ENABLE_EXTERNAL_TOOLS = False
    Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    init_db()
    # 启动后台靶场
    server = threading.Thread(
        target=lambda: uvicorn.run(lab_app, host="127.0.0.1", port=8088, log_level="error"),
        daemon=True
    )
    server.start()
    time.sleep(1.5)
    yield
    settings.DATABASE_PATH = old_database_path
    settings.REPORTS_DIR = old_reports_dir
    settings.ENABLE_EXTERNAL_TOOLS = old_external_tools

def test_full_pipeline_against_lab():
    async def _async_test():
        # 创建测试任务
        conn = get_db_connection()
        cursor = conn.cursor()
        task_id = "test-task-pipeline-01"
        now = "2026-08-26T12:00:00"
        scan_scope = {
            "max_depth": 3,
            "max_pages": 30,
            "qps_limit": 10.0,
            "custom_sensitive_keywords": ["扶持补贴资金", "机密"]
        }
        cursor.execute("""
        INSERT OR REPLACE INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
        VALUES (?, '自动化靶场全流程测试', 'http://127.0.0.1:8088', '["127.0.0.1"]', ?, 'PENDING', 0, '就绪', ?)
        """, (task_id, json.dumps(scan_scope), now))
        conn.commit()
        conn.close()

        # 运行编排器
        orchestrator = InspectionOrchestrator(task_id)
        result = await orchestrator.run()

        # 验证巡检结果
        assert result["task_id"] == task_id
        summary = result["summary"]
        findings = result["findings"]

        # 验证各类核心安全隐患均被精准检出
        categories = [f["category"] for f in findings]
        titles = [f["title"] for f in findings]

        # 1. 验证敏感数据检出 (身份证、手机、银行卡、自定义关键词)
        assert "SENSITIVE" in categories
        assert any("身份证" in t for t in titles)
        assert any("手机号码" in t for t in titles)
        assert any("银行卡" in t for t in titles)
        assert any("扶持补贴资金" in t for t in titles)

        # 2. 验证暗链与篡改检出
        assert "TAMPER" in categories
        assert any("暗链" in t for t in titles)
        assert any("涂鸦" in t or "篡改" in t for t in titles)
        assert any("挖矿" in t or "挂马" in t for t in titles)

        # 3. 验证漏洞与弱配置检出 (.env/.git 泄露、CORS缺陷、安全标头缺失)
        assert "VULN" in categories
        assert any("Git" in t for t in titles)
        assert any(".env" in t for t in titles)
        assert any("CORS" in t for t in titles)

        # 4. 验证安全评分计算正确性
        assert summary["security_score"] < 80

        # 5. 基于版本化标注集计算检测指标，不使用手工填写结论
        truth_path = Path(__file__).parent / "fixtures" / "local_lab_ground_truth.json"
        ground_truth = json.loads(truth_path.read_text(encoding="utf-8"))
        metrics = evaluate_findings(findings, ground_truth)
        assert metrics["positive_sample_count"] == 19
        assert metrics["negative_sample_count"] == 4
        assert metrics["overall"]["tp"] == 19, {
            "missed": metrics["missed_sample_ids"],
            "unmatched": [
                {"title": finding.get("title"), "url": finding.get("url")}
                for finding in findings
                if finding.get("id") in metrics["unmatched_finding_ids"]
            ],
            "overall": metrics["overall"],
        }
        assert metrics["overall"]["fn"] == 0
        assert metrics["overall"]["fp"] == 0
        assert metrics["overall"]["tn"] == 4

    asyncio.run(_async_test())
