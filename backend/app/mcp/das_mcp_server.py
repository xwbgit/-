#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DAS Sentinel Agent - Model Context Protocol (MCP) Server
Exposes automated security posture inspection, vulnerability auditing, 
exploit chain analysis, and OWASP compliance tools via standard MCP JSON-RPC 2.0 (stdio).
"""

import sys
import json
import asyncio
import uuid
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

# Enforce UTF-8 stdio
if sys.platform == "win32":
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app.database import init_db, get_db_connection
from backend.app.agent.orchestrator import InspectionOrchestrator
from plugins.scanner_core.vuln_detector import VulnerabilityDetector
from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler

init_db()

TOOLS = [
    {
        "name": "das_security_audit",
        "description": "执行全面的 Web 目标自动化安全巡检与漏洞风险评估，识别架构拓扑、高危弱点、敏感泄露与安全配置缺陷",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "待审计的目标 Web 站点 URL (如 https://msgbox-merc.vercel.app/)"
                },
                "auth_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "允许巡检与探针的授权主域名列表 (如 [\"msgbox-merc.vercel.app\"])"
                },
                "max_depth": {
                    "type": "integer",
                    "default": 2,
                    "description": "资产爬取最大深度 (默认 2)"
                },
                "max_pages": {
                    "type": "integer",
                    "default": 15,
                    "description": "最大爬取与审计页面数 (默认 15)"
                }
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "das_get_task_report",
        "description": "查询历史安全巡检任务的完整漏洞清单、架构拓扑、安全评分与加固建议",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {
                    "type": "string",
                    "description": "巡检任务 ID"
                }
            },
            "required": ["task_id"]
        }
    },
    {
        "name": "das_analyze_exploit_chain",
        "description": "对指定的漏洞类型或发现项进行 4-Stage 渗透利用链推演 (入口探测 -> 流量穿透 -> 核心利用 -> 数据脱裤)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vulnerability_title": {
                    "type": "string",
                    "description": "漏洞标题或类型 (如 'SQL 注入', '环境变量泄露', 'REST API 未授权访问', 'XSS 跨站脚本')"
                },
                "target_url": {
                    "type": "string",
                    "description": "漏洞发生的 URL 资产地址"
                },
                "param": {
                    "type": "string",
                    "description": "存在缺陷的参数或请求头名称"
                }
            },
            "required": ["vulnerability_title", "target_url"]
        }
    },
    {
        "name": "das_quick_scan_owasp",
        "description": "快速对目标站点执行轻量级 OWASP Top 10 安全基线与合规审计 (标头、SSL、CSP、CORS、JS 凭据、SRI)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "目标 Web 站点 URL"
                }
            },
            "required": ["target_url"]
        }
    }
]

async def handle_security_audit(args: Dict[str, Any]) -> Dict[str, Any]:
    target_url = args.get("target_url", "").strip()
    if not target_url:
        return {"error": "Missing target_url"}
    
    auth_domains = args.get("auth_domains")
    if not auth_domains:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        auth_domains = [parsed.netloc.split(':')[0]] if parsed.netloc else ["localhost"]

    max_depth = int(args.get("max_depth", 2))
    max_pages = int(args.get("max_pages", 15))

    task_id = str(uuid.uuid4())
    now = datetime.now().isoformat()

    scan_scope = {
        "max_depth": max_depth,
        "max_pages": max_pages,
        "qps_limit": 5.0,
        "custom_sensitive_keywords": []
    }

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
    VALUES (?, ?, ?, ?, ?, 'PENDING', 0, 'MCP 任务启动', ?)
    """, (task_id, f"MCP 巡检: {target_url}", target_url, json.dumps(auth_domains), json.dumps(scan_scope), now))
    conn.commit()
    conn.close()

    orchestrator = InspectionOrchestrator(task_id)
    result = await orchestrator.run()
    return result

async def handle_get_task_report(args: Dict[str, Any]) -> Dict[str, Any]:
    task_id = args.get("task_id", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    task_row = cursor.fetchone()
    if not task_row:
        conn.close()
        return {"error": f"Task {task_id} not found"}

    cursor.execute("SELECT * FROM findings WHERE task_id = ?", (task_id,))
    findings_rows = cursor.fetchall()
    conn.close()

    task_dict = dict(task_row)
    if task_dict.get("summary"):
        try:
            task_dict["summary"] = json.loads(task_dict["summary"])
        except Exception:
            pass

    findings = []
    for r in findings_rows:
        fd = dict(r)
        if fd.get("evidence"):
            try:
                fd["evidence"] = json.loads(fd["evidence"])
            except Exception:
                pass
        findings.append(fd)

    return {
        "task": task_dict,
        "total_findings": len(findings),
        "findings": findings
    }

def handle_analyze_exploit_chain(args: Dict[str, Any]) -> Dict[str, Any]:
    mock_finding = {
        "title": args.get("vulnerability_title", ""),
        "url": args.get("target_url", ""),
        "param": args.get("param", ""),
        "severity": "HIGH",
        "category": "VULN"
    }
    chain = VulnerabilityDetector.construct_exploit_chain(mock_finding)
    return {
        "target_url": args.get("target_url"),
        "vulnerability": args.get("vulnerability_title"),
        "exploit_chain": chain
    }

async def handle_quick_scan_owasp(args: Dict[str, Any]) -> Dict[str, Any]:
    target_url = args.get("target_url", "").strip()
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    auth_domains = [parsed.netloc.split(':')[0]] if parsed.netloc else ["localhost"]

    crawler = AssetCrawler(base_url=target_url, auth_domains=auth_domains, max_depth=1, max_pages=3)
    crawled = await crawler.crawl()
    detector = VulnerabilityDetector(target_url, auth_domains)
    findings = await detector.scan_all(crawled["pages"], crawl_metadata=crawled)

    high_impact = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")]
    compliance = [f for f in findings if f.get("severity") in ("LOW", "INFO")]

    return {
        "target_url": target_url,
        "total_findings": len(findings),
        "high_impact_vulnerabilities_count": len(high_impact),
        "compliance_headers_count": len(compliance),
        "high_impact_findings": high_impact,
        "compliance_findings": compliance
    }

def process_mcp_request_sync(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    msg_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "das-sentinel-mcp-server",
                    "version": "1.2.0"
                }
            }
        }

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})

        try:
            if tool_name == "das_security_audit":
                res = asyncio.run(handle_security_audit(tool_args))
            elif tool_name == "das_get_task_report":
                res = asyncio.run(handle_get_task_report(tool_args))
            elif tool_name == "das_analyze_exploit_chain":
                res = handle_analyze_exploit_chain(tool_args)
            elif tool_name == "das_quick_scan_owasp":
                res = asyncio.run(handle_quick_scan_owasp(tool_args))
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"}
                }

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res, ensure_ascii=False, indent=2)
                        }
                    ]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32000, "message": f"Tool execution failed: {str(e)}"}
            }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method '{method}' not implemented"}
        }

def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line_str = line.strip()
            if not line_str:
                continue

            req = json.loads(line_str)
            resp = process_mcp_request_sync(req)
            if resp:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }
            sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
