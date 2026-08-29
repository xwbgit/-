import json
from pathlib import Path

import aiohttp
import pytest

from backend.app.agent.orchestrator import InspectionOrchestrator, scanner_registry
from backend.app.agent.verifier import FindingVerifier
from backend.app.baseline.scheduler_service import SchedulerService
from backend.app.config import settings
from backend.app.database import get_db_connection, init_db
from backend.app.main import _mark_running_tasks_interrupted, _pending_task_ids, _recover_pending_tasks
from backend.app.models.task import TaskCreateRequest
from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
from plugins.scanner_core.vuln_detector import VulnerabilityDetector


def configure_temp_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(settings, "REPORTS_DIR", str(tmp_path / "reports"))
    Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    init_db()


def test_task_defaults_match_backend_limits():
    request = TaskCreateRequest(name="defaults", target_url="http://example.test", auth_domains=["example.test"])
    assert request.max_pages == settings.DEFAULT_MAX_PAGES
    assert request.qps_limit == settings.DEFAULT_RATE_LIMIT_QPS
    assert request.max_pages <= 500
    assert request.qps_limit <= 20


def test_task_requires_explicit_matching_authorization():
    with pytest.raises(ValueError, match="授权域名"):
        TaskCreateRequest(name="missing-scope", target_url="http://example.test")
    with pytest.raises(ValueError, match="不在已确认"):
        TaskCreateRequest(
            name="wrong-scope",
            target_url="https://admin.example.test",
            auth_domains=["other.test"]
        )


@pytest.mark.anyio
async def test_source_code_probe_requires_code_signatures():
    """源码路径必须同时满足状态、非 HTML 和代码特征，避免普通文本误报。"""
    class FakeResponse:
        def __init__(self, status, body, content_type):
            self.status = status
            self._body = body
            self.headers = {"Content-Type": content_type}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self, errors="replace"):
            return self._body

    class FakeSession:
        def get(self, url, **kwargs):
            if url.endswith("/src"):
                return FakeResponse(
                    200,
                    "from sanic import Sanic\n@app.route('/admin')\nclass Pollute:\n    pass\n\napp = Sanic(__name__)\nreturn app\n",
                    "text/plain; charset=utf-8",
                )
            return FakeResponse(404, "not found", "text/plain; charset=utf-8")

    detector = VulnerabilityDetector("https://example.test", ["example.test"])
    findings = await detector._probe_high_risk_endpoints(FakeSession())
    source_findings = [item for item in findings if "/src" in item.get("title", "")]
    assert len(source_findings) == 1
    assert source_findings[0]["verified"] == 1
    assert source_findings[0]["evidence"]["response_status"] == 200
    with pytest.raises(ValueError, match="用户名或密码"):
        TaskCreateRequest(
            name="credential-in-url",
            target_url="https://admin:plain-secret@example.test",
            auth_domains=["example.test"],
        )


def test_invalid_cron_is_rejected_before_registration():
    with pytest.raises(ValueError, match="5 个字段"):
        SchedulerService.validate_cron_expr("0 2 * *")
    with pytest.raises(ValueError, match="Cron 表达式无效"):
        SchedulerService.validate_cron_expr("99 2 * * *")


class FailingRequest:
    async def __aenter__(self):
        raise aiohttp.ClientConnectionError("offline")

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FailingSession:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        return FailingRequest()


@pytest.mark.anyio
async def test_retest_connection_failure_keeps_original_status(monkeypatch):
    monkeypatch.setattr(aiohttp, "ClientSession", FailingSession)
    finding = {
        "url": "http://offline.test/risk",
        "category": "VULN",
        "title": "疑似风险",
        "status": "OPEN",
        "evidence": {}
    }
    result = await FindingVerifier.retest_single_finding(finding)
    assert result["retested"] is False
    assert result["is_still_vulnerable"] is None
    assert result["status_suggested"] == "OPEN"


def test_scheduled_run_creates_independent_history(monkeypatch, tmp_path):
    configure_temp_storage(monkeypatch, tmp_path)
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO tasks (
            id, name, target_url, auth_domains, scan_scope, cron_expr,
            status, progress, current_stage, created_at, run_kind
        ) VALUES ('schedule-1', '每日巡检', 'http://example.test', '["example.test"]', '{}',
                  '0 2 * * *', 'SCHEDULED', 0, '等待触发', '2026-08-28', 'MANUAL')
        """
    )
    conn.commit()
    conn.close()

    first = SchedulerService.create_scan_run("schedule-1", "SCHEDULED_RUN")
    second = SchedulerService.create_scan_run("schedule-1", "SCHEDULED_RUN")
    assert first != second

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, parent_task_id, status, cron_expr FROM tasks WHERE parent_task_id = 'schedule-1' ORDER BY created_at"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    assert all(row["status"] == "PENDING" for row in rows)
    assert all(row["cron_expr"] == "" for row in rows)


@pytest.mark.anyio
async def test_startup_reconciliation_interrupts_running_and_requeues_pending(monkeypatch, tmp_path):
    configure_temp_storage(monkeypatch, tmp_path)
    conn = get_db_connection()
    for task_id, status in (("running-1", "RUNNING"), ("pending-1", "PENDING"), ("schedule-1", "SCHEDULED")):
        conn.execute(
            """
            INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
            VALUES (?, ?, 'http://example.test', '["example.test"]', '{}', ?, 0, 'test', ?)
            """,
            (task_id, task_id, status, task_id),
        )
    conn.commit()
    conn.close()

    interrupted = _mark_running_tasks_interrupted("重启中断")
    assert interrupted == ["running-1"]
    assert _pending_task_ids() == ["pending-1"]

    calls = []

    class FakeOrchestrator:
        def __init__(self, task_id):
            self.task_id = task_id

        async def run(self):
            calls.append(self.task_id)

    monkeypatch.setattr("backend.app.agent.orchestrator.InspectionOrchestrator", FakeOrchestrator)
    await _recover_pending_tasks(_pending_task_ids())
    assert calls == ["pending-1"]

    conn = get_db_connection()
    status = conn.execute("SELECT status FROM tasks WHERE id = 'running-1'").fetchone()["status"]
    conn.close()
    assert status == "INTERRUPTED"


@pytest.mark.anyio
async def test_disabled_detection_flags_skip_scanners_and_persist_report(monkeypatch, tmp_path):
    configure_temp_storage(monkeypatch, tmp_path)
    scan_scope = {
        "max_depth": 1,
        "max_pages": 5,
        "qps_limit": 1.0,
        "enable_vuln_check": False,
        "enable_tamper_check": False,
        "enable_sensitive_check": False
    }
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
        VALUES ('policy-off', '策略关闭测试', 'http://example.test', '["example.test"]', ?, 'PENDING', 0, '等待', '2026-08-28')
        """,
        (json.dumps(scan_scope),)
    )
    conn.commit()
    conn.close()

    calls = []

    class AssetCrawler:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, context):
            calls.append("AssetCrawler")
            context.crawled_pages = [{
                "url": context.target_url,
                "title": "Example",
                "status": 200,
                "depth": 0,
                "dom_hash": "abc",
                "html_content": "<html><title>Example</title></html>"
            }]

    class VulnerabilityDetector:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, context):
            calls.append("VulnerabilityDetector")

    class TamperDetector(VulnerabilityDetector):
        pass

    class SensitiveInspector(VulnerabilityDetector):
        pass

    monkeypatch.setattr(scanner_registry, "discover_scanners", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        scanner_registry,
        "get_all_scanners",
        lambda: [AssetCrawler, VulnerabilityDetector, TamperDetector, SensitiveInspector]
    )
    monkeypatch.setattr(
        ArchitectureFingerprintDetector,
        "detect_architecture",
        staticmethod(lambda *args, **kwargs: {"layers": [], "summary": "test"})
    )

    result = await InspectionOrchestrator("policy-off").run()
    assert calls == ["AssetCrawler"]
    trace = {item["scanner"]: item for item in result["summary"]["execution_trace"]}
    assert trace["VulnerabilityDetector"]["status"] == "SKIPPED"
    assert trace["TamperDetector"]["status"] == "SKIPPED"
    assert trace["SensitiveInspector"]["status"] == "SKIPPED"
    assert Path(result["summary"]["report_path"]).exists()

    conn = get_db_connection()
    task = conn.execute("SELECT status, current_stage FROM tasks WHERE id = 'policy-off'").fetchone()
    conn.close()
    assert task["status"] == "COMPLETED"
    assert "报告已固化" in task["current_stage"]


@pytest.mark.anyio
async def test_empty_crawl_is_not_reported_as_healthy(monkeypatch, tmp_path):
    """真实目标无可分析响应时，结果必须标记为不完整而不是虚假的 100 分。"""
    configure_temp_storage(monkeypatch, tmp_path)
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
        VALUES ('empty-target', '空响应目标', 'http://offline.test', '[\"offline.test\"]', '{}', 'PENDING', 0, '等待', '2026-08-28')
        """
    )
    conn.commit()
    conn.close()

    class EmptyCrawler:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, context):
            context.crawled_pages = []
            context.static_assets = set()
            context.external_links = []

    monkeypatch.setattr(scanner_registry, "discover_scanners", lambda *args, **kwargs: None)
    monkeypatch.setattr(scanner_registry, "get_all_scanners", lambda: [EmptyCrawler])
    monkeypatch.setattr(
        ArchitectureFingerprintDetector,
        "detect_architecture",
        staticmethod(lambda *args, **kwargs: {"layers": [], "summary": "empty"})
    )

    result = await InspectionOrchestrator("empty-target").run()
    assert result["summary"]["security_score"] is None
    assert result["summary"]["scan_quality"] == "INCOMPLETE_NO_PAGE_RESPONSES"
    assert "不能据此判断目标安全" in result["summary"]["scan_quality_note"]
