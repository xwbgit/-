import pytest
import os
import json
from backend.app.agent.verifier import FindingVerifier
from backend.app.baseline.report_service import ReportService
from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
from backend.app.database import init_db, get_db_connection
from backend.app.config import settings

def test_url_normalization_dedup():
    findings = [
        {
            "category": "VULN",
            "title": "HSTS 缺失",
            "url": "http://127.0.0.1:8088/portal/index?_t=123456&PHPSESSID=abc",
            "param": ""
        },
        {
            "category": "VULN",
            "title": "HSTS 缺失",
            "url": "http://127.0.0.1:8088/portal/index?_t=789012&PHPSESSID=xyz",
            "param": ""
        },
        {
            "category": "VULN",
            "title": "不同漏洞",
            "url": "http://127.0.0.1:8088/portal/index",
            "param": ""
        }
    ]
    deduped = FindingVerifier.deduplicate_findings(findings)
    assert len(deduped) == 2
    assert deduped[0]["instance_count"] == 2
    assert deduped[1]["instance_count"] == 1

def test_architecture_fingerprint():
    pages = [
        {
            "url": "https://msgbox-merc.vercel.app/",
            "headers": {"server": "Vercel", "x-vercel-id": "hnd1::iad1"},
            "html_content": '<div id="__next">Hello Next.js React app</div>'
        }
    ]
    findings = []
    arch = ArchitectureFingerprintDetector.detect_architecture("https://msgbox-merc.vercel.app/", pages, findings)
    assert len(arch["layers"]) == 5
    # Frontend should detect React / Next.js
    assert "React" in arch["layers"][0]["component"]["name"]
    # Web server should detect Vercel Edge
    assert "Vercel" in arch["layers"][1]["component"]["name"]
    # Vercel 网关不能单独证明后端一定是 Node.js
    assert arch["layers"][2]["component"]["detected"] is False

def test_light_report_generation(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "DATABASE_PATH", str(tmp_path / "report-test.db"))
    monkeypatch.setattr(settings, "REPORTS_DIR", str(tmp_path / "reports"))
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # insert dummy task and finding
    cursor.execute("""
    INSERT OR REPLACE INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at, summary)
    VALUES ('task-test-rep', '测试报告任务', 'http://127.0.0.1:8088', '[]', '{}', 'COMPLETED', 100, '完成', '2026-08-26', '{"security_score": 92, "status_level": "HEALTHY", "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1}}')
    """)
    cursor.execute(
        """
        INSERT OR REPLACE INTO findings (id, task_id, category, title, severity, url, param, evidence, impact, remediation, verified, cvss_score, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, 0, 5.0, 'OPEN', '2026-08-26')
        """,
        (
            "f-test-xss",
            "task-test-rep",
            "VULN",
            '<img src=x onerror="alert(1)">',
            "MEDIUM",
            "http://127.0.0.1:8088/xss",
            json.dumps({"matched_snippet": "</pre><script>alert(1)</script>"}),
            "<b>attacker-controlled impact</b>",
            "<a href=javascript:alert(1)>fix</a>",
        ),
    )
    cursor.execute("""
    INSERT OR REPLACE INTO findings (id, task_id, category, title, severity, url, param, evidence, impact, remediation, verified, cvss_score, status, created_at)
    VALUES ('f-test-1', 'task-test-rep', 'VULN', 'Git 泄露', 'HIGH', 'http://127.0.0.1:8088/.git/config', '', '{"matched_snippet": "repositoryformatversion = 0"}', '影响源码安全', '禁止访问 .git', 1, 7.5, 'OPEN', '2026-08-26')
    """)
    conn.commit()
    conn.close()
    
    report_file = ReportService.generate_html_report('task-test-rep')
    assert os.path.exists(report_file)
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "background: #f8fafc" in content or "background: #ffffff" in content
        assert "Git 泄露" in content
        assert "92" in content
        assert '<img src=x onerror="alert(1)">' not in content
        assert "</pre><script>alert(1)</script>" not in content
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
