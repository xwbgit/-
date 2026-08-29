import json
import logging
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Dict, Any, List
from backend.app.config import settings
from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.report")

class ReportService:
    """自动化安全巡检报告生成服务 (支持 现代浅色主题 HTML、JSON、Markdown 及打印 PDF 样式)"""

    @classmethod
    def generate_html_report(cls, task_id: str) -> str:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        task_row = cursor.fetchone()
        if not task_row:
            conn.close()
            raise ValueError(f"Task {task_id} not found")
        task = dict(task_row)
        
        cursor.execute("SELECT * FROM findings WHERE task_id = ? ORDER BY cvss_score DESC", (task_id,))
        findings = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        summary = json.loads(task.get("summary") or "{}")
        sev_counts = summary.get("severity_counts", {})
        raw_score = summary.get("security_score")
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
            score = raw_score
        else:
            try:
                score = float(raw_score) if raw_score not in (None, "") else None
            except (TypeError, ValueError):
                score = None
        status_level = summary.get("status_level", "未生成安全评分")
        scan_quality_note = summary.get("scan_quality_note", "")
        
        score_color = "#64748b" if score is None else ("#16a34a" if score >= 85 else ("#d97706" if score >= 60 else "#dc2626"))
        
        findings_html = ""
        for idx, f in enumerate(findings, 1):
            evidence = json.loads(f.get("evidence") or "{}")
            sev = f.get("severity", "LOW")
            badge_bg = {
                "CRITICAL": "#fee2e2",
                "HIGH": "#ffedd5",
                "MEDIUM": "#fef3c7",
                "LOW": "#e0f2fe",
                "INFO": "#f1f5f9"
            }.get(sev, "#f1f5f9")
            badge_text = {
                "CRITICAL": "#b91c1c",
                "HIGH": "#c2410c",
                "MEDIUM": "#b45309",
                "LOW": "#0369a1",
                "INFO": "#475569"
            }.get(sev, "#475569")
            badge_border = {
                "CRITICAL": "#fca5a5",
                "HIGH": "#fdba74",
                "MEDIUM": "#fde68a",
                "LOW": "#bae6fd",
                "INFO": "#cbd5e1"
            }.get(sev, "#cbd5e1")
            
            snippet = escape(str(evidence.get("matched_snippet", "")))
            safe_title = escape(str(f.get("title") or ""))
            safe_url = escape(str(f.get("url") or ""))
            safe_impact = escape(str(f.get("impact") or ""))
            safe_remediation = escape(str(f.get("remediation") or ""))
            safe_severity = escape(str(sev))
            safe_cvss = escape(str(f.get("cvss_score", 0.0)))
            
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-num">#{idx}</span>
                    <span class="severity-badge" style="background:{badge_bg}; color:{badge_text}; border:1px solid {badge_border};">{safe_severity}</span>
                    <span class="finding-title">{safe_title}</span>
                    <span class="cvss-pill">CVSS {safe_cvss}</span>
                </div>
                <div class="finding-body">
                    <p><strong>📍 风险目标：</strong><code style="color:#0284c7; background:#f1f5f9; padding:2px 6px; border-radius:4px;">{safe_url}</code></p>
                    <p style="margin-top:6px;"><strong>⚠️ 危害影响与原理：</strong>{safe_impact}</p>
                    <div class="evidence-box">
                        <strong style="color:#0284c7;">🔍 现场证据链 (Evidence Snapshot)：</strong>
                        <pre>{snippet}</pre>
                    </div>
                    <div class="remediation-box">
                        <strong style="color:#15803d;">🛠️ 专家整改与代码修复建议：</strong>
                        <p style="margin-top:4px; color:#166534;">{safe_remediation}</p>
                    </div>
                </div>
            </div>
            """

        safe_task_name = escape(str(task.get("name") or ""))
        safe_target_url = escape(str(task.get("target_url") or ""))
        safe_started_at = escape(str(task.get("started_at") or ""))
        safe_finished_at = escape(str(task.get("finished_at") or ""))
        safe_status_level = escape(str(status_level))
        safe_score = escape("--" if score is None else str(score))
        safe_scan_quality_note = escape(str(scan_quality_note))

        html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>网站安全智能巡检与敏感信息防泄露评估报告 - {safe_task_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
            background: #f8fafc;
            color: #0f172a;
            margin: 0;
            padding: 24px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            padding: 36px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 4px 16px rgba(0,0,0,0.06);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 20px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            font-size: 22px;
            color: #0f172a;
            margin: 0;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 24px;
            font-size: 13px;
            color: #475569;
            background: #f8fafc;
            padding: 16px 20px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        .score-card {{
            text-align: center;
            padding: 24px;
            background: #f8fafc;
            border-radius: 10px;
            margin-bottom: 24px;
            border: 1px solid #e2e8f0;
            border-left: 6px solid {score_color};
        }}
        .score-num {{
            font-size: 48px;
            font-weight: 800;
            color: {score_color};
        }}
        .stats-row {{
            display: flex;
            gap: 14px;
            margin-bottom: 30px;
        }}
        .stat-box {{
            flex: 1;
            background: #ffffff;
            padding: 16px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e2e8f0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .stat-val {{
            font-size: 22px;
            font-weight: 800;
            margin-top: 6px;
        }}
        .finding-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 18px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 18px;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
        }}
        .finding-num {{
            font-weight: 700;
            color: #64748b;
            font-size: 12px;
        }}
        .finding-title {{
            font-weight: 700;
            font-size: 14px;
            color: #0f172a;
        }}
        .severity-badge {{
            font-size: 11px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .cvss-pill {{
            margin-left: auto;
            font-size: 11px;
            background: #e0f2fe;
            color: #0369a1;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 700;
        }}
        .finding-body {{
            padding: 18px;
            font-size: 13px;
            line-height: 1.6;
        }}
        .evidence-box {{
            background: #f8fafc;
            padding: 14px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
            margin: 12px 0;
        }}
        .evidence-box pre {{
            margin: 8px 0 0 0;
            color: #0f172a;
            font-family: Consolas, Monaco, monospace;
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 12px;
            background: #ffffff;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #cbd5e1;
        }}
        .remediation-box {{
            background: #f0fdf4;
            border-left: 4px solid #16a34a;
            padding: 12px 16px;
            border-radius: 4px;
            margin-top: 12px;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #64748b;
            margin-top: 40px;
            border-top: 1px solid #e2e8f0;
            padding-top: 20px;
            line-height: 1.6;
        }}
        .btn-print {{
            background: #0284c7;
            color: #ffffff;
            border: none;
            padding: 9px 18px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 700;
            font-size: 13px;
            box-shadow: 0 2px 6px rgba(2, 132, 199, 0.3);
            transition: background 0.15s;
        }}
        .btn-print:hover {{
            background: #0369a1;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .container {{ box-shadow: none; border: none; padding: 0; }}
            .btn-print {{ display: none; }}
            .meta-grid, .score-card, .stat-box, .finding-card {{ background: #fff; border: 1px solid #ccc; }}
            .evidence-box {{ background: #f8f8f8; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🛡️ 网站安全智能巡检与敏感信息防泄露评估报告</h1>
                <p style="margin: 6px 0 0 0; font-size: 13px; color: #64748b;">DAS-SentinelAgent (安恒星巡安全智能体) 自动生成 · 官方交付标准</p>
            </div>
            <button class="btn-print" onclick="window.print()">🖨️ 导出 / 打印 PDF</button>
        </div>

        <div class="meta-grid">
            <div><strong>任务名称：</strong>{safe_task_name}</div>
            <div><strong>目标站点：</strong><code>{safe_target_url}</code></div>
            <div><strong>巡检周期/时间：</strong>{safe_started_at} ~ {safe_finished_at}</div>
            <div><strong>综合安全态势：</strong><strong style="color:{score_color};">{safe_status_level}</strong></div>
            <div><strong>结果质量：</strong>{safe_scan_quality_note or "未记录"}</div>
        </div>

        <div class="score-card">
            <div style="font-size: 14px; color: #64748b; font-weight: 700;">综合安全态势评分</div>
            <div class="score-num">{safe_score} <span style="font-size: 20px; color:#64748b;">/ 100</span></div>
            <div style="font-size: 13px; color: #475569; margin-top: 4px;">{safe_status_level}</div>
        </div>

        <div class="stats-row">
            <div class="stat-box" style="border-top: 3px solid #dc2626;">
                <div style="color:#64748b; font-size:12px; font-weight:600;">严重风险 (Critical)</div>
                <div class="stat-val" style="color:#dc2626;">{sev_counts.get('CRITICAL', 0)}</div>
            </div>
            <div class="stat-box" style="border-top: 3px solid #ea580c;">
                <div style="color:#64748b; font-size:12px; font-weight:600;">高危风险 (High)</div>
                <div class="stat-val" style="color:#ea580c;">{sev_counts.get('HIGH', 0)}</div>
            </div>
            <div class="stat-box" style="border-top: 3px solid #d97706;">
                <div style="color:#64748b; font-size:12px; font-weight:600;">中危风险 (Medium)</div>
                <div class="stat-val" style="color:#d97706;">{sev_counts.get('MEDIUM', 0)}</div>
            </div>
            <div class="stat-box" style="border-top: 3px solid #2563eb;">
                <div style="color:#64748b; font-size:12px; font-weight:600;">低危与合规 (Low/Info)</div>
                <div class="stat-val" style="color:#2563eb;">{sev_counts.get('LOW', 0) + sev_counts.get('INFO', 0)}</div>
            </div>
        </div>

        <h3 style="border-left: 4px solid #0284c7; padding-left: 12px; margin: 28px 0 16px 0; color:#0f172a;">📋 详细风险隐患与整改建议清单 ({len(findings)} 项)</h3>
        
        {findings_html if findings else '<p style="text-align:center; color:#16a34a; padding:40px; font-size:15px; font-weight:700;">当前授权范围和检测策略下未产生风险发现。</p>'}

        <div class="footer">
            <p><strong>DAS-SentinelAgent 本地巡检报告</strong></p>
            <p>报告生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 数据来自任务快照与审计日志</p>
        </div>
    </div>
</body>
</html>
"""
        report_path = Path(settings.REPORTS_DIR) / f"report_{task_id}.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return str(report_path)

    @classmethod
    def generate_src_submission_markdown(cls, task_id: str) -> str:
        """生成符合企业 SRC 漏洞提报标准的专业 Markdown 报告"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        task_row = cursor.fetchone()
        if not task_row:
            conn.close()
            raise ValueError(f"Task {task_id} not found")
        task = dict(task_row)
        
        cursor.execute("SELECT * FROM findings WHERE task_id = ? AND src_type = 'SRC_EXPLOITABLE' ORDER BY cvss_score DESC", (task_id,))
        src_findings = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        md_lines = [
            f"# 企业 SRC 漏洞响应平台标准提报单",
            f"",
            f"**目标系统**: `{task.get('target_url')}`  ",
            f"**巡检任务 ID**: `{task.get('id')}`  ",
            f"**提报时间**: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`  ",
            f"**安全测试原则遵守声明**: 本次测试严格遵循授权测试、最小化原则与无害原则，未对业务系统造成任何破坏，未进行内网横向移动与敏感数据外传。  ",
            f"",
            f"---",
            f"",
            f"## 🎯 SRC 有效实战漏洞汇总 (共 {len(src_findings)} 项)",
            f""
        ]
        
        if not src_findings:
            md_lines.append("> 当前任务未固化可直接提交 SRC 的实战漏洞记录；这不代表系统不存在待复核风险或基线问题，请结合完整巡检报告和复测结果判断。\n")
        else:
            for idx, f in enumerate(src_findings, 1):
                ev = json.loads(f.get("evidence") or "{}")
                md_lines.extend([
                    f"### {idx}. [{f.get('severity')}] {f.get('title')}",
                    f"",
                    f"- **漏洞类型**: `{f.get('category')}`",
                    f"- **威胁等级**: **{f.get('severity')}** (CVSS 评分: `{f.get('cvss_score')}`)",
                    f"- **影响 URL**: `{f.get('url')}`",
                    f"- **关联参数 / 位置**: `{f.get('param') or 'N/A'}`",
                    f"",
                    f"#### 🔍 漏洞利用与复现步骤 (PoC)",
                    f"```http",
                    f"{ev.get('matched_snippet') or json.dumps(ev, ensure_ascii=False, indent=2)}",
                    f"```",
                    f"",
                    f"#### 💥 业务危害与影响证明",
                    f"{f.get('impact')}",
                    f"",
                    f"#### 🛠️ 官方修复建议",
                    f"{f.get('remediation')}",
                    f"",
                    f"---",
                    f""
                ])
                
        return "\n".join(md_lines)

