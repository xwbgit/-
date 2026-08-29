import logging
import asyncio
import json
import aiohttp
from typing import Dict, Any, List, Set
from plugins.core.base import BaseScanner, ScanContext
from plugins.scanner_extensions.exploit_chain.ai_mutator import AdaptiveMutator

logger = logging.getLogger("das_sentinel.rest_api_prober")

class RestApiProber(BaseScanner):
    """
    REST API 探测与接口边界发现引擎 (REST API & Interface Prober)
    方向：api_fuzzer
    职责：
    1. 基于已发现的 API 路由，执行轻量级安全探针与 Swagger / OpenAPI 接口探测
    2. 发现未授权 API 接口、GraphQL 查询端点及异常返回状态
    3. 将 API 探测风险无缝注入 ScanContext 统一风险池
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.probed_endpoints: Set[str] = set()
        self.mutator = AdaptiveMutator()

    async def run(self, context: ScanContext) -> None:
        logger.info(f"[ApiFuzzer] 启动 API 接口安全探测... 候选接口数: {len(context.api_endpoints)}")
        
        findings: List[Dict[str, Any]] = []
        sensitive_patterns = ["swagger", "api-docs", "graphql", "actuator", "metrics"]
        
        semaphore = asyncio.Semaphore(10)  # 限制并发数
        req_timeout = aiohttp.ClientTimeout(total=10)
        
        async def probe_endpoint(ep: str, session: aiohttp.ClientSession):
            self.probed_endpoints.add(ep)
            for pat in sensitive_patterns:
                if pat in ep.lower():
                    async with semaphore:
                        try:
                            ua_headers = {"User-Agent": "Mozilla/5.0"}
                            orig_req = {"method": "GET", "url": ep, "headers": ua_headers}
                            
                            async with session.get(ep, headers=ua_headers, allow_redirects=False) as resp:
                                status = resp.status
                                body_preview = (await resp.text())[:500]
                                
                                if status == 403 and "actuator" in pat:
                                    # 尝试调用 AI Mutator
                                    logger.info(f"[ApiFuzzer] 遇到 WAF 拦截(403)，尝试 AI 自适应变异: {ep}")
                                    mutated = await self.mutator.mutate_payload(orig_req, f"403 Forbidden - WAF blocked access to {ep}")
                                    if mutated:
                                        logger.info(f"[ApiFuzzer] 获得 AI 变异 Payload: {mutated}")
                                        # BUG-3 FIX: 用变异后的 payload 发送真实的第二次请求验证
                                        mutated_url = mutated.get("url", ep)
                                        mutated_headers = mutated.get("headers", ua_headers)
                                        try:
                                            async with session.get(mutated_url, headers=mutated_headers, allow_redirects=False) as resp2:
                                                status2 = resp2.status
                                                body2 = (await resp2.text())[:500]
                                                if status2 == 200:
                                                    # 真实绕过成功
                                                    evidence_data = {
                                                        "raw_request": orig_req,
                                                        "raw_response": {"status_code": status, "body": body_preview},
                                                        "mutated_request": mutated,
                                                        "mutated_response": {"status_code": status2, "body": body2}
                                                    }
                                                    findings.append({
                                                        "task_id": context.task_id,
                                                        "category": "VULN",
                                                        "level": "HIGH",
                                                        "title": f"AI 自适应绕过 WAF: {pat}",
                                                        "target": ep,
                                                        "description": f"端点 {ep} 被 403 拦截，AI 变异后请求 {mutated_url} 成功获得 200 响应。",
                                                        "evidence": json.dumps(evidence_data, ensure_ascii=False),
                                                        "remediation": "修复底层 WAF 过滤规则不足，或限制端口访问。"
                                                    })
                                                else:
                                                    logger.info(f"[ApiFuzzer] AI 变异后请求仍被拦截 (HTTP {status2}): {mutated_url}")
                                        except Exception as e2:
                                            logger.debug(f"[ApiFuzzer] AI 变异后请求发送失败: {e2}")
                                            
                                elif status in [200, 301, 302, 401]:
                                    # 记录轻量级发现（如检测到敏感接口）
                                    findings.append({
                                        "task_id": context.task_id,
                                        "category": "VULN",
                                        "level": "MEDIUM",
                                        "title": f"发现敏感 API / 文档端点: {pat}",
                                        "target": ep,
                                        "description": f"在目标站点提取到开放的 API 文档或管理端点: {ep} (HTTP {status})",
                                        "evidence": json.dumps({"matched": pat, "url": ep, "status": status, "body": body_preview}),
                                        "remediation": "建议生产环境关闭 Swagger/Actuator 等调试与内部文档暴露，增加网关鉴权。"
                                    })
                        except Exception as e:
                            logger.debug(f"[ApiFuzzer] Probe error on {ep}: {e}")
                    break  # 匹配到一个 pattern 就跳出内层循环
        
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), timeout=req_timeout) as session:
            tasks = [probe_endpoint(ep, session) for ep in context.api_endpoints]
            if tasks:
                await asyncio.gather(*tasks)

        if findings:
            context.add_findings(findings)
            logger.info(f"[ApiFuzzer] 探测到 API 潜在风险 {len(findings)} 项")
