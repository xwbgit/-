from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.agent.orchestrator import InspectionOrchestrator
from backend.app.api import tasks
from backend.app.config import settings
from backend.app.database import init_db


def _client(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DATABASE_PATH", str(tmp_path / "api-contract.db"))
    monkeypatch.setattr(settings, "REPORTS_DIR", str(tmp_path / "reports"))
    Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
    init_db()

    async def no_network_run(self):
        return {"task_id": self.task_id, "findings": [], "summary": {}}

    monkeypatch.setattr(InspectionOrchestrator, "run", no_network_run)
    app = FastAPI()
    app.include_router(tasks.router, prefix="/api/v1")
    return TestClient(app)


def test_frontend_quick_scan_payload_is_accepted_and_rerun_gets_new_id(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    response = client.post("/api/v1/tasks", json={
        "name": "即时巡检",
        "target_url": "http://127.0.0.1:8088",
        "auth_domains": ["127.0.0.1"],
        "max_depth": 3,
        "max_pages": 100,
        "qps_limit": 5.0,
    })
    assert response.status_code == 200, response.text
    source_id = response.json()["id"]
    assert response.json()["status"] == "PENDING"

    rerun = client.post(f"/api/v1/tasks/{source_id}/rerun")
    assert rerun.status_code == 200, rerun.text
    assert rerun.json()["task_id"].startswith("run-")
    assert rerun.json()["task_id"] != source_id


def test_invalid_cron_returns_422_without_creating_task(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    response = client.post("/api/v1/tasks", json={
        "name": "错误 Cron",
        "target_url": "https://example.test",
        "auth_domains": ["example.test"],
        "cron_expr": "99 2 * * *",
    })
    assert response.status_code == 422
    assert client.get("/api/v1/tasks").json() == []
