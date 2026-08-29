import time
import json
import logging
import uuid
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import aiohttp

from backend.app.config import settings
from backend.app.database import get_db_connection
from backend.app.agent.orchestrator import InspectionOrchestrator
from plugins.scanner_core.vuln_detector import VulnerabilityDetector

router = APIRouter(prefix="/msgbox", tags=["MsgBox 开发者接口与专项测试工具"])
logger = logging.getLogger("das_sentinel.msgbox_tool")

DEFAULT_API_TOKEN = settings.MSGBOX_API_TOKEN.strip()
DEFAULT_TARGET_URL = settings.MSGBOX_TARGET_URL.strip()

class MsgBoxApiRequest(BaseModel):
    base_url: str = Field(default=DEFAULT_TARGET_URL, description="已获授权的目标站点根 URL")
    endpoint: str = "/api/messages"
    method: str = "GET"
    api_token: str = Field(default=DEFAULT_API_TOKEN, description="可选的目标站点 API Token，由调用方或部署环境提供")
    custom_headers: Optional[Dict[str, str]] = None
    query_params: Optional[Dict[str, str]] = None
    body_json: Optional[str] = None

class MsgBoxScanLaunchRequest(BaseModel):
    base_url: str = Field(default=DEFAULT_TARGET_URL, description="已获授权的目标站点根 URL")
    api_token: str = Field(default=DEFAULT_API_TOKEN, description="可选的目标站点 API Token，由调用方或部署环境提供")
    max_depth: int = 2
    max_pages: int = 15

def _validate_target_url(base_url: str) -> str:
    """校验工作台目标，避免空值、凭据和绝对 endpoint 导致意外请求。"""
    from urllib.parse import urlparse

    value = (base_url or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(status_code=422, detail="base_url 必须是有效的 http/https URL")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail="base_url 不得携带明文用户名或密码")
    return value.rstrip("/")


def _validate_endpoint(endpoint: str) -> str:
    from urllib.parse import urlparse

    value = (endpoint or "").strip()
    parsed = urlparse(value)
    if not value or parsed.scheme or parsed.netloc:
        raise HTTPException(status_code=422, detail="endpoint 只能是目标站点内的相对路径")
    return value


@router.get("/config")
def get_msgbox_config():
    """获取可选 MsgBox 工作台配置；不返回任何明文凭证。"""
    token = DEFAULT_API_TOKEN
    masked_token = (token[:4] + "…" + token[-4:]) if len(token) >= 8 else ""
    return {
        "target_url": DEFAULT_TARGET_URL,
        # 保留原字段形状以兼容旧前端，但永远不从服务端返回明文 Token。
        "default_token": "",
        "masked_token": masked_token,
        "token_length": len(token),
        "configured": bool(DEFAULT_TARGET_URL),
        "presets": [
            {
                "id": "get_messages",
                "name": "📥 消息拉取与列表接口",
                "method": "GET",
                "endpoint": "/api/messages",
                "description": "查询与提取消息列表数据",
                "sample_body": ""
            },
            {
                "id": "send_message",
                "name": "📤 消息投递与发布接口",
                "method": "POST",
                "endpoint": "/api/send",
                "description": "向消息箱投递新消息",
                "sample_body": json.dumps({"content": "测试消息内容", "sender": "DAS_Tester"}, ensure_ascii=False, indent=2)
            },
            {
                "id": "check_status",
                "name": "🛡️ 开发者鉴权与健康状态",
                "method": "GET",
                "endpoint": "/api/status",
                "description": "校验 API Token 有效性与服务运行状态",
                "sample_body": ""
            },
            {
                "id": "admin_probe",
                "name": "🔍 管理员接口与越权探针",
                "method": "GET",
                "endpoint": "/api/admin",
                "description": "探测管理员配置与未授权访问边界",
                "sample_body": ""
            }
        ]
    }

@router.post("/execute")
async def execute_msgbox_request(req: MsgBoxApiRequest):
    """代理执行对目标 MsgBox 站点的 API 请求并收集详细通信与安全研判指标"""
    base_url = _validate_target_url(req.base_url)
    endpoint = _validate_endpoint(req.endpoint)
    target_full_url = urljoin(base_url + "/", endpoint.lstrip("/"))
    
    headers = {
        "User-Agent": settings.DEFAULT_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    }
    token = (req.api_token or "").strip()
    if token:
        headers.update({
            "Authorization": f"Bearer {token}",
            "X-API-Key": token,
            "X-Developer-Token": token,
        })
    if req.custom_headers:
        headers.update(req.custom_headers)

    start_time = time.time()
    try:
        timeout = aiohttp.ClientTimeout(total=10.0)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout, trust_env=False) as session:
            kwargs = {}
            if req.query_params:
                kwargs["params"] = req.query_params
            if req.method.upper() in ("POST", "PUT", "PATCH") and req.body_json:
                try:
                    kwargs["json"] = json.loads(req.body_json)
                except Exception:
                    kwargs["data"] = req.body_json
                    headers["Content-Type"] = "application/json"

            async with session.request(req.method.upper(), target_full_url, **kwargs) as resp:
                elapsed_ms = round((time.time() - start_time) * 1000, 2)
                resp_text = await resp.text(errors="replace")
                resp_headers = dict(resp.headers)
                
                # 尝试格式化 JSON
                parsed_json = None
                try:
                    parsed_json = json.loads(resp_text)
                except Exception:
                    pass

                # 安全研判指标
                security_insights = []
                if resp.status == 200:
                    security_insights.append("🟢 请求成功 (HTTP 200 OK)")
                elif resp.status in (401, 403):
                    security_insights.append(f"🛡️ 鉴权拦截或权限受限 (HTTP {resp.status})")
                elif resp.status == 404:
                    security_insights.append("⚪ 接口路径不存在或处于 SPA 路由兜底")
                elif resp.status >= 500:
                    security_insights.append(f"⚠️ 服务端内部异常 (HTTP {resp.status})")

                if "x-vercel-mitigated" in resp_headers:
                    security_insights.append(f"🛡️ 命中 Vercel 边缘网关策略: {resp_headers['x-vercel-mitigated']}")
                if "content-security-policy" not in resp_headers:
                    security_insights.append("⚠️ 响应缺失 Content-Security-Policy 标头")

                return {
                    "status_code": resp.status,
                    "elapsed_ms": elapsed_ms,
                    "target_url": target_full_url,
                    "method": req.method.upper(),
                    "response_headers": resp_headers,
                    "response_body_raw": resp_text[:10000],
                    "response_json": parsed_json,
                    "security_insights": security_insights
                }
    except Exception as e:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        logger.warning(f"MsgBox API execution error: {e}")
        return {
            "status_code": 0,
            "elapsed_ms": elapsed_ms,
            "target_url": target_full_url,
            "method": req.method.upper(),
            "error": str(e),
            "security_insights": [f"❌ 网络请求异常或连接超时: {str(e)}"]
        }

@router.post("/launch_scan")
async def launch_authenticated_scan(req: MsgBoxScanLaunchRequest):
    """为已授权 MsgBox 目标创建巡检任务；凭证不写入数据库。"""
    base_url = _validate_target_url(req.base_url)
    task_id = str(uuid.uuid4())
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    auth_domains = [parsed.hostname] if parsed.hostname else []

    scan_scope = {
        "max_depth": req.max_depth,
        "max_pages": req.max_pages,
        "qps_limit": 5.0,
        "api_token_configured": bool((req.api_token or "").strip()),
        "custom_sensitive_keywords": ["api_key", "secret", "token", "password", "msgbox"]
    }

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
    VALUES (?, ?, ?, ?, ?, 'PENDING', 0, 'MsgBox 专项安全巡检就绪', ?)
    """, (task_id, f"MsgBox API 专项安全巡检: {base_url}", base_url, json.dumps(auth_domains), json.dumps(scan_scope), now))
    conn.commit()
    conn.close()

    orchestrator = InspectionOrchestrator(task_id)
    # 异步在后台调度
    import asyncio
    asyncio.create_task(orchestrator.run())

    return {
        "status": "SUCCESS",
        "task_id": task_id,
        "message": f"已成功为 MsgBox 站点 {base_url} 启动专项安全巡检任务",
        "created_at": now
    }
