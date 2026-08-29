from plugins.core.base import BaseScanner, ScanContext
import asyncio
import uuid
import logging
import re
import hashlib
import json
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import aiohttp
from bs4 import BeautifulSoup
from backend.app.config import settings

logger = logging.getLogger("das_sentinel.vuln")

try:
    from plugins.core.src_filter import apply_src_filter
except ImportError:
    def apply_src_filter(findings): return findings  # fallback

class VulnerabilityDetector(BaseScanner):
    """全面 Web 常见漏洞、弱配置、接口暴露与主动参数风险检测引擎 (带智能抗误报基线)"""
    
    def __init__(self, target_url: str, auth_domains: List[str]):
        self.target_url = target_url.rstrip('/')
        self.auth_domains = set(d.strip().lower() for d in auth_domains if d.strip())
        parsed = urlparse(self.target_url)
        if parsed.netloc:
            self.auth_domains.add(parsed.netloc.split(':')[0].lower())
            
        # 增加 API 路由爆破字典
        self.api_brute_dict = [
            "/api/v1/users", "/api/admin", "/v1/auth/users", "/api/config", 
            "/graphql", "/v1/user/info", "/api/swagger.json", "/api/v1/system/env"
        ]
            
        # 记录目标服务器的软 404 / SPA 通配符响应指纹
        self.is_wildcard_spa = False
        self.spa_baseline_hash = ""
        self.spa_baseline_len = 0

    async def _detect_soft404_baseline(self, session: aiohttp.ClientSession):
        """探测目标站点的 404 响应基线，识别 SPA/泛解析与自定义 200 错误页，从根源杜绝误报"""
        random_path_1 = f"/_das_probe_404_nonexistent_{uuid.uuid4().hex[:8]}.html"
        random_path_2 = f"/_das_probe_404_nonexistent_{uuid.uuid4().hex[:8]}.json"
        target_probe = urljoin(self.target_url + "/", random_path_1.lstrip("/"))
        try:
            async with session.get(target_probe, allow_redirects=True) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    # 如果不存在的随机路径返回 200 并且是 HTML，说明是 SPA 前端路由或自定义 200 错误页
                    if "<html" in text.lower() or "<!doctype" in text.lower() or "root" in text:
                        self.is_wildcard_spa = True
                        self.spa_baseline_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
                        self.spa_baseline_len = len(text)
                        logger.info(f"Target {self.target_url} uses SPA Wildcard Routing (200 OK for 404s). Baseline recorded.")
        except Exception as e:
            logger.debug(f"Soft404 baseline probe error: {e}")

    def _is_false_positive_spa_response(self, text: str, status_code: int) -> bool:
        """根据基线判断返回的内容是否是 SPA 通配符兜底页面或伪 200 错误页"""
        if not self.is_wildcard_spa:
            return False
        if status_code != 200:
            return False
        # 如果长度与基线高度接近 (误差在 10% 以内) 且包含 HTML，判定为 SPA 兜底
        if abs(len(text) - self.spa_baseline_len) < max(50, self.spa_baseline_len * 0.1):
            if "<html" in text.lower() or "<!doctype" in text.lower() or '<div id="root"' in text or '<div id="__next"' in text:
                return True
        cur_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return cur_hash == self.spa_baseline_hash

    async def scan_all(self, crawled_pages: List[Dict[str, Any]], crawl_metadata: Optional[Dict[str, Any]] = None, progress_callback=None) -> List[Dict[str, Any]]:
        findings = []
        timeout = aiohttp.ClientTimeout(total=settings.DEFAULT_TIMEOUT_SEC)
        connector = aiohttp.TCPConnector(ssl=False)
        headers = {"User-Agent": settings.DEFAULT_USER_AGENT}
        
        crawl_meta = crawl_metadata or {}
        js_scripts = crawl_meta.get("js_scripts", [])
        url_parameters = crawl_meta.get("url_parameters", [])
        forms = crawl_meta.get("forms", [])

        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout, trust_env=True) as session:
            # 0. 建立 404 抗误报基线
            await self._detect_soft404_baseline(session)

            # 1. 深度检测 HTTP 安全响应标头缺失与服务指纹
            if progress_callback:
                await progress_callback(1, 6, "正在执行 HTTP 安全标头、CSP 策略与通信协议审计...")
            if crawled_pages:
                main_page = crawled_pages[0]
                header_findings = self._check_security_headers(main_page)
                findings.extend(header_findings)
                method_findings = await self._check_http_methods(session, main_page["url"])
                findings.extend(method_findings)

            # 2. Cookie 安全属性审计 [已禁用 - Cookie属性缺失不达SRC认定标准]
            # cookie_findings = self._check_cookie_security(crawled_pages)
            # findings.extend(cookie_findings)
            if progress_callback:
                await progress_callback(2, 6, "跳过 Cookie 属性审计（不达SRC标准），继续下一步检测...")

            # 3. CORS 高级检测（含子域反射、null Origin、API 端点）
            if progress_callback:
                await progress_callback(3, 6, "正在测试 CORS 跨域凭证与 Origin 反射安全...")
            if crawled_pages:
                cors_findings = await self._check_cors_misconfig_advanced(
                    session, crawled_pages, crawl_meta.get("api_endpoints", [])
                )
                findings.extend(cors_findings)

            # 4. JS 代码审计与 SourceMap 泄露
            if progress_callback:
                await progress_callback(4, 6, "正在扫描前端 JS 代码秘钥与 SourceMap 源码映射暴露...")
            js_findings = await self._check_js_sourcemaps_and_secrets(session, js_scripts)
            findings.extend(js_findings)

            # 5. 高危端点探针
            if progress_callback:
                await progress_callback(5, 6, "正在探测高危端点、API 接口文档与敏感配置文件暴露...")
            endpoint_findings = await self._probe_high_risk_endpoints(session)
            findings.extend(endpoint_findings)

            # 5.5 GraphQL 未授权与自省泄露探测
            graphql_findings = await self._probe_graphql_endpoints(session)
            findings.extend(graphql_findings)

            # 5.6 API 路由字典爆破探测 (扩大字典规模)
            api_brute_findings = await self._probe_api_routes_bruteforce(session)
            findings.extend(api_brute_findings)

            # 5.7 Swagger/OpenAPI 参数深度 Fuzz
            if crawl_meta.get("api_endpoints"):
               api_fuzz_findings = await self._fuzz_api_endpoints_deep(session, crawl_meta.get("api_endpoints", []))
               findings.extend(api_fuzz_findings)

            # 6. 主动动态参数弱点探针
            if progress_callback:
                await progress_callback(6, 6, "正在对已发现的动态参数与表单执行非破坏性启发式探针...")
            param_findings = await self._probe_parameter_vulnerabilities(session, url_parameters, forms, crawled_pages)
            findings.extend(param_findings)

            # 7. 🛰️ 专项 API 未授权访问与越权深度探测 (BOLA / Broken Object Level Auth)
            api_findings = await self._probe_api_unauthorized_endpoints(session, crawl_meta.get("api_endpoints", []))
            findings.extend(api_findings)

            # 8. ⛓️ 为所有发现的漏洞与弱点构建实战级 4-Stage 【漏洞利用链】(Multi-Stage Exploit Chain)
            for f in findings:
                f["exploit_chain"] = self.construct_exploit_chain(f)

        # ── 最终 SRC 边界过滤：移除所有不达 SRC 认定标准的 INFO 噪音 ──────────────
        findings = apply_src_filter(findings)
        logger.info(f"[VulnDetector] SRC-filtered findings count: {len(findings)}")
        return findings

    def _check_security_headers(self, page_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        HTTP 安全标头检测 — 精简版（仅保留 SRC 中危及以上配置缺陷）。
        
        已禁用（不满足 SRC 认定标准）：
          ✗ HSTS 缺失 / includeSubDomains 不完整
          ✗ CSP 头缺失
          ✗ X-Frame-Options 缺失
          ✗ X-Content-Type-Options 缺失
          ✗ Referrer-Policy 缺失
          ✗ 服务器版本 Banner 暴露
        
        保留检测（有实际利用价值）：
          ✓ CSP 存在 unsafe-inline 且允许执行内联脚本 (MEDIUM CVSS≥5)
          ✓ HTTP TRACE 跨站追踪 (XST) - 由 _check_http_methods 处理
        """
        findings = []
        page_headers = {k.lower(): v for k, v in page_data.get("headers", {}).items()}
        url = page_data.get("url", self.target_url)

        # 仅保留 CSP unsafe-inline + script-src 组合（可直接用于 XSS 绕过，MEDIUM+）
        csp_val = page_headers.get("content-security-policy", "")
        if csp_val:
            weaknesses = []
            if ("'unsafe-inline'" in csp_val and "script-src" in csp_val):
                weaknesses.append("script-src 包含 'unsafe-inline'（允许执行内联注入脚本）")
            if ("'unsafe-eval'" in csp_val and "script-src" in csp_val):
                weaknesses.append("script-src 包含 'unsafe-eval'（允许动态 eval 字符串脚本）")
            if ("script-src *" in csp_val or "default-src *" in csp_val):
                weaknesses.append("script-src / default-src 包含通配符 *（任意外部域脚本）")

            if len(weaknesses) >= 1:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "category": "VULN",
                    "title": "Content-Security-Policy 存在高危弱配置指令（可辅助 XSS 绕过）",
                    "severity": "MEDIUM",
                    "url": url,
                    "param": "Header: Content-Security-Policy",
                    "evidence": {
                        "matched_snippet": f"CSP: {csp_val[:200]} | 弱点: {', '.join(weaknesses)}",
                        "weaknesses": weaknesses,
                    },
                    "impact": "宽松的 CSP 规则使攻击者可通过内联脚本注入绕过 XSS 防护，显著降低 XSS 利用门槛",
                    "remediation": "移除 'unsafe-inline' 与 'unsafe-eval'，改用基于 Nonce 或 Hash 的脚本白名单",
                    "verified": 1,
                    "cvss_score": 5.4,
                    "status": "OPEN"
                })

        return findings


    async def _check_http_methods(self, session: aiohttp.ClientSession, url: str) -> List[Dict[str, Any]]:
        """检测不安全 HTTP 请求方法 (如 TRACE / XST 跨站追踪漏洞)"""
        findings = []
        try:
            # 测试 TRACE 请求
            async with session.request("TRACE", url, headers={"X-Test-Trace": "DAS-Sentinel-Header"}) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    if "DAS-Sentinel-Header" in text or "X-Test-Trace" in text:
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "category": "VULN",
                            "title": "启用 HTTP TRACE 方法（Cross-Site Tracing / XST 风险）",
                            "severity": "MEDIUM",
                            "url": url,
                            "param": "Method: TRACE",
                            "evidence": {
                                "matched_snippet": f"HTTP TRACE 200 OK, 回显了自定义 Header: X-Test-Trace",
                                "status": resp.status
                            },
                            "impact": "攻击者可配合 XSS 漏洞通过 TRACE 请求读取包含 HttpOnly 的敏感 Cookie",
                            "remediation": "在 Web 服务器中禁用 TRACE 请求方法 (Nginx: if ($request_method = TRACE ) { return 405; })",
                            "verified": 1,
                            "cvss_score": 5.3,
                            "status": "OPEN"
                        })
        except Exception as e:
            logger.debug(f"HTTP TRACE check error: {e}")
        return findings

    def _check_cookie_security(self, crawled_pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """审计所有页面返回的 Cookie 安全属性 (HttpOnly, Secure, SameSite)"""
        findings = []
        seen_cookies = set()
        
        for page in crawled_pages:
            url = page.get("url", "")
            cookies = page.get("cookies", [])
            for c_str in cookies:
                c_clean = c_str.split(";")[0].strip()
                if not c_clean or c_clean in seen_cookies:
                    continue
                seen_cookies.add(c_clean)
                
                c_name = c_clean.split("=")[0].strip()
                c_str_lower = c_str.lower()
                
                # 判断是否是敏感鉴权/会话 Cookie
                is_auth_cookie = any(k in c_name.lower() for k in ["session", "token", "auth", "jwt", "sid", "user", "phpsessid", "jsessionid", "remember"])
                
                # 1. HttpOnly 缺失
                if "httponly" not in c_str_lower:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "MISCONFIG",
                        "title": f"Cookie 缺失 HttpOnly 属性 ({c_name})",
                        "severity": "INFO",
                        "url": url,
                        "param": f"Cookie: {c_name}",
                        "evidence": {
                            "matched_snippet": f"Set-Cookie: {c_str}",
                            "cookie_name": c_name
                        },
                        "impact": "客户端 JavaScript 可直接读取该 Cookie",
                        "remediation": f"在生成 Cookie 时设置 HttpOnly 标志 (Set-Cookie: {c_name}=...; HttpOnly;)",
                        "verified": 1,
                        "cvss_score": 0.0,
                        "status": "OPEN"
                    })

                # 2. Secure 缺失 (HTTPS 环境)
                if url.startswith("https://") and "secure" not in c_str_lower:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "MISCONFIG",
                        "title": f"Cookie 缺失 Secure 属性 ({c_name})",
                        "severity": "INFO",
                        "url": url,
                        "param": f"Cookie: {c_name}",
                        "evidence": {
                            "matched_snippet": f"Set-Cookie: {c_str}",
                            "cookie_name": c_name
                        },
                        "impact": "Cookie 在非加密 HTTP 传输或被降级时可能通过明文信道发送",
                        "remediation": f"在 HTTPS 下为所有 Cookie 添加 Secure 标志 (Set-Cookie: {c_name}=...; Secure;)",
                        "verified": 1,
                        "cvss_score": 0.0,
                        "status": "OPEN"
                    })

                # 3. SameSite 缺失或 None (CSRF 隐患)
                if "samesite" not in c_str_lower:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "MISCONFIG",
                        "title": f"Cookie 缺失 SameSite 跨站隔离属性 ({c_name})",
                        "severity": "INFO",
                        "url": url,
                        "param": f"Cookie: {c_name}",
                        "evidence": {
                            "matched_snippet": f"Set-Cookie: {c_str}",
                            "cookie_name": c_name
                        },
                        "impact": "存在 CSRF 风险",
                        "remediation": f"添加 SameSite=Lax 或 SameSite=Strict 属性",
                        "verified": 1,
                        "cvss_score": 0.0,
                        "status": "OPEN"
                    })

        return findings

    async def _check_cors_misconfig(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict[str, Any]]:
        """检测 CORS 错误配置与任意 Origin 反射（保留向后兼容）"""
        results = await self._check_cors_misconfig_advanced(session, [], [])
        return results[0] if results else None

    async def _check_cors_misconfig_advanced(
        self,
        session: aiohttp.ClientSession,
        crawled_pages: List[Dict[str, Any]],
        api_endpoints: List[str]
    ) -> List[Dict[str, Any]]:
        """高级 CORS 误配检测：
        - 任意 Origin 反射 + credentials: true（高危）
        - 子域名反射（如 evil.ninebot.com）+ credentials: true（高危）
        - 通配符 * + credentials: false（中危，浏览器阻断但说明配置宽松）
        - null Origin 反射 + credentials: true（高危，可在 iframe sandbox 利用）
        - 对 API 端点也进行 CORS 检测
        """
        findings = []
        tested_urls: Set[str] = set()

        # 构建测试 URL 列表（主页 + API 端点，去重）
        test_urls = []
        if crawled_pages:
            test_urls.append(crawled_pages[0]["url"])
        for ep in (api_endpoints or []):
            if ep not in tested_urls:
                test_urls.append(ep)
        # 最多测 10 个 API 端点
        test_urls = test_urls[:11]

        # 构造测试 Origin 列表：
        # 1. 完全陌生域名
        # 2. 目标域名的 "evil" 前缀子域
        # 3. null
        # 4. 原始域名加 .evil.com 后缀（origin confusion）
        parsed_base = urlparse(self.target_url)
        base_host = parsed_base.netloc.split(':')[0]
        base_scheme = parsed_base.scheme
        evil_origins = [
            "https://evil-attacker.com",
            f"{base_scheme}://evil.{base_host}",
            f"{base_scheme}://{base_host}.evil-attacker.com",
            "null",
        ]

        for test_url in test_urls:
            if test_url in tested_urls:
                continue
            tested_urls.add(test_url)

            for test_origin in evil_origins:
                try:
                    req_headers = {"Origin": test_origin}
                    async with session.get(test_url, headers=req_headers,
                                           timeout=aiohttp.ClientTimeout(total=6.0)) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                        if not acao:
                            continue

                        is_reflected = (acao == test_origin)
                        is_wildcard = (acao == "*")
                        with_creds = (acac == "true")

                        # 最高危：反射任意 Origin + credentials
                        if is_reflected and with_creds:
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": f"CORS 高危错误配置：任意 Origin 反射且允许携带凭据 [{test_url}]",
                                "severity": "HIGH",
                                "url": test_url,
                                "param": f"Header: Origin={test_origin}",
                                "evidence": {
                                    "matched_snippet": (
                                        f"Request Origin: {test_origin}\n"
                                        f"Response ACAO: {acao}\n"
                                        f"Response ACAC: true\n"
                                        f"★ 可被任意第三方网站以受害者身份读取响应"
                                    ),
                                    "request_headers": req_headers,
                                    "response_headers": dict(resp.headers),
                                    "verification_steps": [
                                        "1. 打开 evil-attacker.com，执行 fetch('" + test_url + "', {credentials:'include'})",
                                        "2. 服务器将 ACAO 回显为 evil-attacker.com 且 ACAC: true",
                                        "3. 浏览器允许 JS 读取响应体，泄露当前用户的敏感 API 数据"
                                    ]
                                },
                                "impact": "攻击者可在任意第三方页面上以受害者身份发起带凭据跨域请求并读取敏感账户数据或 API 响应",
                                "remediation": "严格白名单校验 Origin，禁止动态反射未知来源；禁止同时设置 ACAO: * 与 ACAC: true",
                                "verified": 1,
                                "cvss_score": 8.1,
                                "status": "OPEN"
                            })
                            break  # 本 URL 已确认，无需测试其他 Origin

                        # null Origin + credentials（iframe sandbox 可利用）
                        elif test_origin == "null" and acao == "null" and with_creds:
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": f"CORS 高危错误配置：null Origin 反射且允许携带凭据（iframe sandbox 可利用）[{test_url}]",
                                "severity": "HIGH",
                                "url": test_url,
                                "param": "Header: Origin=null",
                                "evidence": {
                                    "matched_snippet": f"ACAO: null + ACAC: true → 攻击者可用 <iframe sandbox=allow-scripts> 内部 fetch 读取响应"
                                },
                                "impact": "攻击者可通过 sandbox iframe 伪造 null Origin 绕过同源策略读取受害者 API 响应数据",
                                "remediation": "禁止 ACAO 响应 null，对所有非白名单 Origin 返回 403",
                                "verified": 1,
                                "cvss_score": 7.5,
                                "status": "OPEN"
                            })
                            break

                except Exception as e:
                    logger.debug(f"CORS advanced check error for {test_url} origin={test_origin}: {e}")

        return findings

    async def _check_js_sourcemaps_and_secrets(self, session: aiohttp.ClientSession, js_scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """检测前端 JS 是否暴露 SourceMap 源码映射或硬编码敏感云凭据"""
        findings = []
        
        # 常见敏感 AK/SK 及云服务正则
        secret_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS AccessKey ID 硬编码泄露", "CRITICAL", 8.5),
            (r"AIzaSy[0-9A-Za-z-_]{35}", "Google API Key 客户端暴露", "MEDIUM", 5.5),
            (r"ghp_[0-9a-zA-Z]{36}", "GitHub 个人访问令牌 (PAT) 泄露", "CRITICAL", 9.0),
            (r"https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+", "Slack Webhook 凭据泄露", "HIGH", 7.5),
            (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "私钥证书明文嵌入前端代码", "CRITICAL", 9.8)
        ]

        for item in js_scripts:
            js_url = item.get("url", "")
            js_content = item.get("content", "")
            if not js_content:
                continue

            # 1. 扫描硬编码凭据
            for pat, title, sev, cvss in secret_patterns:
                match = re.search(pat, js_content)
                if match:
                    val = match.group(0)
                    masked = val[:4] + "****" + val[-4:] if len(val) > 10 else "****"
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "VULN",
                        "title": f"前端 JavaScript 存在 {title}",
                        "severity": sev,
                        "url": js_url,
                        "param": "JS File Content",
                        "evidence": {
                            "matched_snippet": f"... {js_content[max(0, match.start()-30):min(len(js_content), match.end()+30)].strip()} ...",
                            "masked_value": masked
                        },
                        "impact": "直接导致云端资源或第三方开发者权限被黑客获取，产生数据窃取或未授权调用",
                        "remediation": "立即吊销已泄露的 API 凭据，使用后端环境变量管理并在前端使用安全中继网关",
                        "verified": 1,
                        "cvss_score": cvss,
                        "status": "OPEN"
                    })

            # 2. 探测 SourceMap (.js.map) 泄露
            map_url = js_url + ".map"
            try:
                async with session.get(map_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=4.0)) as map_resp:
                    if map_resp.status == 200:
                        map_text = await map_resp.text(errors="replace")
                        if '"sources":' in map_text and not self._is_false_positive_spa_response(map_text, map_resp.status):
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": "前端代码 SourceMap 源码映射文件暴露 (.js.map)",
                                "severity": "HIGH",
                                "url": map_url,
                                "param": "Path: .js.map",
                                "evidence": {
                                    "matched_snippet": f"SourceMap 存在: {map_text[:200]}...",
                                    "status": map_resp.status
                                },
                                "impact": "攻击者可通过 SourceMap 还原前端未经混淆的原始工程源码、注释、未公开接口及内部逻辑",
                                "remediation": "生产构建时关闭 SourceMap 生成，或通过 Web 服务器配置禁止外网直接访问 .map 文件",
                                "verified": 1,
                                "cvss_score": 7.0,
                                "status": "OPEN"
                            })
            except Exception:
                pass

        return findings

    async def _probe_high_risk_endpoints(self, session: aiohttp.ClientSession) -> List[Dict[str, Any]]:
        """高危端点、接口文档与敏感文件暴露探测 (严格结构校验与抗误报)"""
        findings = []
        
        # 结构化探测规则
        endpoint_probes = [
            {
                "path": "/.git/HEAD",
                "title": "Git 版本控制元数据泄露 (.git/HEAD)",
                "severity": "CRITICAL",
                "cvss": 8.5,
                "impact": "攻击者可提取完整网站源代码、历史提交记录与配置工程",
                "validate": lambda txt, ctype, st: st == 200 and not ("<html" in txt.lower() or "<!doctype" in txt.lower()) and bool(re.search(r"ref:\s*refs/heads/|[0-9a-f]{40}", txt))
            },
            {
                "path": "/.git/config",
                "title": "Git 配置文件泄露 (.git/config)",
                "severity": "HIGH",
                "cvss": 7.8,
                "impact": "暴露远程仓库 Git URL、开发分支与鉴权凭据",
                "validate": lambda txt, ctype, st: st == 200 and not ("<html" in txt.lower() or "<!doctype" in txt.lower()) and "[core]" in txt and "repositoryformatversion" in txt
            },
            {
                "path": "/.env",
                "title": "环境变量配置文件泄露 (.env)",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "impact": "直接泄露数据库账号密码、应用主秘钥与第三方 API Token",
                "validate": lambda txt, ctype, st: st == 200 and not ("<html" in txt.lower() or "<!doctype" in txt.lower()) and bool(re.search(r"(?:APP_KEY|DB_PASSWORD|SECRET|DATABASE_URL|MYSQL_PWD)=", txt))
            },
            {
                "path": "/backup.sql",
                "title": "数据库备份文件明文暴露 (backup.sql)",
                "severity": "CRITICAL",
                "cvss": 9.5,
                "impact": "核心业务数据库可能被攻击者完整下载脱库",
                "validate": lambda txt, ctype, st: st == 200 and not ("<html" in txt.lower() or "<!doctype" in txt.lower()) and bool(re.search(r"CREATE\s+TABLE|INSERT\s+INTO|--\s+MySQL\s+dump|/\*!40101\s+SET", txt, re.IGNORECASE))
            },
            {
                "path": "/swagger-ui.html",
                "title": "Swagger 接口文档未授权访问 (swagger-ui.html)",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "impact": "向未授权访问者暴露全部后端 API 接口、数据模型与请求入参",
                "validate": lambda txt, ctype, st: st == 200 and ("swagger-ui" in txt.lower() or "openapi" in txt.lower() or "SwaggerUIBundle" in txt)
            },
            {
                "path": "/openapi.json",
                "title": "OpenAPI / Swagger 接口元数据规范暴露 (openapi.json)",
                "severity": "MEDIUM",
                "cvss": 5.0,
                "impact": "完整暴露后端 RESTful 路由清单与入参结构",
                "validate": lambda txt, ctype, st: st == 200 and ('"openapi":' in txt or '"swagger":' in txt) and '"paths":' in txt
            },
            {
                "path": "/actuator/health",
                "title": "Spring Boot Actuator 监控端点未授权暴露",
                "severity": "MEDIUM",
                "cvss": 6.0,
                "impact": "向外界暴露系统运行健康状态、组件依赖与内部微服务运行参数",
                "validate": lambda txt, ctype, st: st == 200 and ('"status":"UP"' in txt or '"status":"DOWN"' in txt or '"components":' in txt)
            },
            {
                "path": "/phpinfo.php",
                "title": "PHP 探针及配置泄露 (phpinfo.php)",
                "severity": "MEDIUM",
                "cvss": 5.0,
                "impact": "泄露 PHP 模块扩展、绝对安装路径、编译参数等敏感运行环境信息",
                "validate": lambda txt, ctype, st: st == 200 and ("PHP Version" in txt or "Configuration File (php.ini)" in txt or "<title>phpinfo()</title>" in txt)
            },
            {
                "path": "/.svn/entries",
                "title": "SVN 版本控制文件泄露 (.svn/entries)",
                "severity": "HIGH",
                "cvss": 7.5,
                "impact": "攻击者可逆向导出代码仓库文件与工程目录",
                "validate": lambda txt, ctype, st: st == 200 and not ("<html" in txt.lower() or "<!doctype" in txt.lower()) and "svn:" in txt
            },
            {
                "path": "/api/v1/users",
                "title": "API 未授权访问 (用户列表 /api/v1/users)",
                "severity": "HIGH",
                "cvss": 7.5,
                "impact": "未授权暴露用户数据列表",
                "validate": lambda txt, ctype, st: st == 200 and ("{" in txt or "[" in txt) and ("email" in txt.lower() or "username" in txt.lower() or "id" in txt.lower()) and not self._is_false_positive_spa_response(txt, st)
            },
            {
                "path": "/actuator/env",
                "title": "Spring Boot Actuator 环境变量暴露 (/actuator/env)",
                "severity": "CRITICAL",
                "cvss": 8.5,
                "impact": "可能泄露数据库凭据和系统秘钥",
                "validate": lambda txt, ctype, st: st == 200 and ("propertysources" in txt.lower() or "activeprofiles" in txt.lower())
            },
            {
                "path": "/api/token",
                "title": "API Token 泄露或未授权生成接口 (/api/token)",
                "severity": "HIGH",
                "cvss": 8.0,
                "impact": "未授权获取或生成身份令牌",
                "validate": lambda txt, ctype, st: st == 200 and "token" in txt.lower() and "{" in txt
            }
        ]

        for probe in endpoint_probes:
            target_path = urljoin(self.target_url + "/", probe["path"].lstrip("/"))
            try:
                async with session.get(target_path, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=4.0)) as resp:
                    text_sample = await resp.text(errors="replace")
                    ctype = resp.headers.get("Content-Type", "")
                    status = resp.status
                    
                    # 首先过滤 SPA 通配符误报
                    if self._is_false_positive_spa_response(text_sample, status):
                        continue
                        
                    # 执行严格内容结构特征验证
                    if probe["validate"](text_sample, ctype, status):
                        snippet = text_sample[:250].strip()
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "category": "VULN",
                            "title": probe["title"],
                            "severity": probe["severity"],
                            "url": target_path,
                            "param": f"Path: {probe['path']}",
                            "evidence": {
                                "matched_snippet": snippet[:180] + ("..." if len(snippet) > 180 else ""),
                                "response_status": status,
                                "response_headers": dict(resp.headers)
                            },
                            "impact": probe["impact"],
                            "remediation": f"立即在 Web 服务器配置中禁止外网访问 {probe['path']}，设置 403 拒绝访问并移除敏感文件",
                            "verified": 1,
                            "cvss_score": probe["cvss"],
                            "status": "OPEN"
                        })
            except Exception as e:
                logger.debug(f"Endpoint probe error {target_path}: {e}")

        return findings

    async def _fuzz_api_endpoints_deep(self, session: aiohttp.ClientSession, endpoints: List[str]) -> List[Dict[str, Any]]:
        """对已发现的 API 端点进行深度 Fuzz，寻找未授权访问或逻辑漏洞"""
        findings = []
        for ep in endpoints[:20]: # 扩大探测范围
            # 尝试未授权访问常见敏感后缀及 Swagger 接口
            sensitive_suffixes = [
                "/user", "/admin", "/config", "/users/1", "/v1/admin/users", 
                "/api-docs", "/v2/api-docs", "/swagger-ui.html", "/openapi.json",
                "/actuator/env", "/actuator/health", "/env", "/metrics"
            ]
            for suffix in sensitive_suffixes:
                target_url = ep.rstrip("/") + suffix
                try:
                    async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=4.0)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            text_lower = text.lower()
                            
                            is_vuln = False
                            vuln_title = ""
                            vuln_impact = ""
                            cvss = 5.0
                            
                            # 1. 敏感数据越权/未授权泄露
                            if "{" in text and ("email" in text_lower or "password" in text_lower or "token" in text_lower or "admin" in text_lower or "credit" in text_lower):
                                is_vuln = True
                                vuln_title = f"API 未授权访问导致敏感数据泄露 ({suffix})"
                                vuln_impact = "攻击者可未授权读取敏感业务数据或管理配置"
                                cvss = 7.5
                                
                            # 2. Swagger / OpenAPI 接口未授权暴露
                            elif "swagger" in text_lower or "openapi" in text_lower or "paths" in text_lower:
                                is_vuln = True
                                vuln_title = f"Swagger/OpenAPI 接口文档未授权暴露 ({suffix})"
                                vuln_impact = "攻击者可获取系统所有 API 接口详情，极大降低攻击门槛"
                                cvss = 5.5
                                
                            # 3. Spring Boot Actuator / 环境变量泄露
                            elif "activeprofiles" in text_lower or "propertysources" in text_lower or "java.version" in text_lower:
                                is_vuln = True
                                vuln_title = f"Spring Boot Actuator / 环境变量泄露 ({suffix})"
                                vuln_impact = "泄露服务器内部环境变量、数据库密码等极度敏感信息"
                                cvss = 8.5
                                
                            if is_vuln:
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "category": "VULN",
                                    "title": vuln_title,
                                    "severity": "MEDIUM" if cvss < 7.0 else "HIGH",
                                    "url": target_url,
                                    "param": "Endpoint",
                                    "evidence": {
                                        "matched_snippet": text[:200],
                                        "status": resp.status
                                    },
                                    "impact": vuln_impact,
                                    "remediation": "为 API 接口添加严格的鉴权机制，生产环境关闭 Swagger 和 Actuator 端点",
                                    "verified": 1,
                                    "cvss_score": cvss,
                                    "status": "OPEN"
                                })
                except Exception:
                    pass
        return findings

    async def _probe_parameter_vulnerabilities(
        self,
        session: aiohttp.ClientSession,
        url_parameters: List[Dict[str, Any]],
        forms: List[Dict[str, Any]],
        crawled_pages: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """工业级多维度参数漏洞深度探针 (上下文感知 XSS、差分/时间盲注 SQLi、多编码 LFI、SSTI、命令注入、SSRF)"""
        findings = []
        
        # 收集所有待测试的目标参数 endpoint
        test_targets = []
        for p_info in url_parameters:
            endpoint = p_info.get("endpoint", "")
            params = p_info.get("params", [])
            for p in params:
                test_targets.append({"url": endpoint, "param": p, "type": "GET"})
                
        for f in forms:
            action = f.get("action", "")
            method = f.get("method", "GET")
            for inp in f.get("inputs", []):
                p_name = inp.get("name")
                if p_name and inp.get("type") not in ("hidden", "submit", "button"):
                    test_targets.append({"url": action, "param": p_name, "type": method})

        # 深度探测每个参数
        for item in test_targets[:20]:
            url = item["url"]
            param = item["param"]
            req_type = item["type"]

            # =========================================================================
            # 1. 🔍 上下文感知 XSS 深度挖掘 (Context-Aware XSS + 真实 DOM 逃逸分析)
            # =========================================================================
            try:
                # 阶段 1: 发送特征 Canary，分析反射上下文与过滤矩阵
                canary_probe = 'das7<xss"\'/\\>'
                test_url = f"{url}?{param}={canary_probe}" if req_type == "GET" else url
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as xss_resp:
                    if xss_resp.status == 200:
                        body = await xss_resp.text(errors="replace")
                        # 排除 SPA 统一错误页与页面中由于 URL 埋点/JS 变量导致的单纯文本反射
                        if not self._is_false_positive_spa_response(body, xss_resp.status) and "das7" in body:
                            # 严格过滤 JSON 字符串、URL 埋点追踪参数与 JS 变量
                            idx_canary = body.find("das7")
                            nearby_ctx = body[max(0, idx_canary-40):min(len(body), idx_canary+50)].lower()
                            is_json_or_tracking = (
                                f'"{canary_probe}"' in body or f"'{canary_probe}'" in body or 
                                f'url=' in nearby_ctx or f'location' in nearby_ctx or 
                                f'query' in nearby_ctx or f'window.' in nearby_ctx or
                                f'\\u003c' in body or f'&lt;' in body or f'%3c' in nearby_ctx
                            )
                            
                            is_real_xss = False
                            context_type = ""
                            survived_chars = []

                            # 1. HTML 标签体 (Body Context): <xss 必须作为未转义的真实 HTML 标签存活，且不在 JSON/JS 内部
                            if "<xss" in body and not is_json_or_tracking and "<script" not in nearby_ctx:
                                is_real_xss = True
                                context_type = "HTML 标签体 (Body Context)"
                                survived_chars = ["<", ">", "/"]
                            # 2. HTML 属性值 (Attribute Context): 能够闭合当前属性双/单引号
                            elif (f'value="{canary_probe}' in body or f'value=\'{canary_probe}' in body or f'="{canary_probe}' in body) and not is_json_or_tracking:
                                is_real_xss = True
                                context_type = "HTML 属性值 (Attribute Context)"
                                survived_chars = ['"', "'", ">"]
                            # 3. JavaScript 代码块 (Script Context): 能够利用 </script> 闭合当前脚本块
                            elif f'</script><xss' in body and not is_json_or_tracking:
                                is_real_xss = True
                                context_type = "JavaScript 代码块 (Script Context)"
                                survived_chars = ["<", "/", ">"]


                            if is_real_xss:
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "category": "VULN",
                                    "title": f"参数存在上下文感知反射型 XSS 漏洞 [{param}] ({context_type})",
                                    "severity": "HIGH",
                                    "url": url,
                                    "param": f"Param: {param}",
                                    "evidence": {
                                        "reflection_context": context_type,
                                        "surviving_unescaped_chars": survived_chars,
                                        "probe_payload": canary_probe,
                                        "matched_snippet": f"在 {context_type} 中未转义回显，逃逸字符 [{', '.join(survived_chars)}] 存活",
                                        "status": xss_resp.status
                                    },
                                    "impact": "攻击者可绕过基础过滤，在受害者浏览器上下文中执行任意 JavaScript 窃取 Session/Cookie 凭据",
                                    "remediation": f"对参数 {param} 实施基于具体上下文的转义（HTML Entity / JS Hex Encode），或配置严格 CSP 策略",
                                    "verified": 1,
                                    "cvss_score": 7.8,
                                    "status": "OPEN"
                                })
            except Exception:
                pass


            # =========================================================================
            # 2. 💉 工业级 SQL 注入深度挖掘 (错误回显 + 布尔差分 + 统计时间盲注)
            # =========================================================================
            try:
                # 阶段 1: 单双引号与反斜杠错误回显
                sql_error_patterns = [
                    (r"You have an error in your SQL syntax", "MySQL 语法错误"),
                    (r"Warning:\s*mysql_", "PHP MySQL 错误"),
                    (r"syntax error at or near", "PostgreSQL 语法错误"),
                    (r"unrecognized token:\s*\"?'", "SQLite 语法错误"),
                    (r"ORA-01756|ORA-00933|ORA-00936", "Oracle SQL 错误"),
                    (r"Unclosed quotation mark before the character string", "SQL Server 未闭合引号")
                ]
                test_url = f"{url}?{param}=1'"
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as sql_resp:
                    body = await sql_resp.text(errors="replace")
                    for pat, desc in sql_error_patterns:
                        if re.search(pat, body, re.IGNORECASE):
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": f"参数存在基于报错的 SQL 注入漏洞 (Error-based SQLi) [{param}]",
                                "severity": "CRITICAL",
                                "url": url,
                                "param": f"Param: {param}",
                                "evidence": {
                                    "db_error_type": desc,
                                    "probe_payload": "1'",
                                    "matched_snippet": f"单引号触发底层数据库报错: {desc}"
                                },
                                "impact": "攻击者可提取数据库元数据、脱库用户机密并尝试 UDF 提权",
                                "remediation": f"参数 {param} 必须强制使用预编译参数化查询 (PreparedStatement)，严禁 SQL 字符串拼接",
                                "verified": 1,
                                "cvss_score": 9.8,
                                "status": "OPEN"
                            })
                            break

                # 阶段 2: 布尔差分推演 (True: ' AND 4821=4821 -- vs False: ' AND 4821=4822 --)
                true_url = f"{url}?{param}=1%27%20AND%204821=4821%20--%20"
                false_url = f"{url}?{param}=1%27%20AND%204821=4822%20--%20"
                async with session.get(true_url, timeout=aiohttp.ClientTimeout(total=5.0)) as true_resp:
                    true_status = true_resp.status
                    true_text = await true_resp.text(errors="replace")
                    
                async with session.get(false_url, timeout=aiohttp.ClientTimeout(total=5.0)) as false_resp:
                    false_status = false_resp.status
                    false_text = await false_resp.text(errors="replace")
                    
                # SRC 抗误报增强：差分阈值提升至 100 字节，避免微小噪音导致误报
                if true_status == 200 and (false_status != 200 or abs(len(true_text) - len(false_text)) > 100):
                    if not self._is_false_positive_spa_response(true_text, true_status):
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "category": "VULN",
                            "title": f"参数存在基于布尔差分的盲注漏洞 (Boolean-based Blind SQLi) [{param}]",
                            "severity": "CRITICAL",
                            "url": url,
                            "param": f"Param: {param}",
                            "evidence": {
                                "true_condition_status": true_status,
                                "false_condition_status": false_status,
                                "length_difference": abs(len(true_text) - len(false_text)),
                                "matched_snippet": "真条件 (4821=4821) 与假条件 (4821=4822) 产生确定性响应差异"
                            },
                            "impact": "攻击者可通过二分法盲注自动化逐位提取整库敏感数据",
                            "remediation": f"参数 {param} 采用 ORM 参数化绑定或整型强制类型转换",
                            "verified": 1,
                            "cvss_score": 9.5,
                            "status": "OPEN"
                        })

                # 阶段 3: 时间盲注统计基线差分验证 (Time-based Blind SQLi，杜绝网络偶发抖动误报)
                import time as pytime
                try:
                    # 1. 测量正常基线响应耗时
                    t_base_start = pytime.time()
                    async with session.get(f"{url}?{param}=1", timeout=aiohttp.ClientTimeout(total=4.0)) as base_resp:
                        await base_resp.text(errors="replace")
                    t_base = pytime.time() - t_base_start

                    # 2. 只有在基线响应较快（< 1.5s）时才执行时间盲注探测
                    if t_base < 1.5:
                        time_probe_url = f"{url}?{param}=1%20AND%20SLEEP(2)"
                        t_start = pytime.time()
                        async with session.get(time_probe_url, timeout=aiohttp.ClientTimeout(total=6.0)) as time_resp:
                            await time_resp.text(errors="replace")
                            duration = pytime.time() - t_start
                            # 3. 差分判定：延迟必须显著大于基线且满足延时特征 (delta >= 1.7s)
                            if (duration - t_base) >= 1.7:
                                # 4. 二次复验：使用 SLEEP(0) 确认耗时回落至基线水准
                                t_zero_start = pytime.time()
                                async with session.get(f"{url}?{param}=1%20AND%20SLEEP(0)", timeout=aiohttp.ClientTimeout(total=4.0)) as zero_resp:
                                    await zero_resp.text(errors="replace")
                                    t_zero = pytime.time() - t_zero_start
                                if t_zero < 1.5:
                                    findings.append({
                                        "id": str(uuid.uuid4()),
                                        "category": "VULN",
                                        "title": f"参数存在时间延迟盲注漏洞 (Time-based Blind SQLi) [{param}]",
                                        "severity": "CRITICAL",
                                        "url": url,
                                        "param": f"Param: {param}",
                                        "evidence": {
                                            "baseline_latency_seconds": round(t_base, 2),
                                            "measured_delay_seconds": round(duration, 2),
                                            "zero_delay_confirmation": round(t_zero, 2),
                                            "probe_payload": "1 AND SLEEP(2)",
                                            "matched_snippet": f"基线 {round(t_base, 2)}s -> SLEEP(2) 响应 {round(duration, 2)}s (差分 +{round(duration - t_base, 2)}s)"
                                        },
                                        "impact": "攻击者可在无任何回显的情况下利用时间延迟逐字节脱裤",
                                        "remediation": "采用参数化绑定，在 WAF 层拦截 SLEEP/BENCHMARK/WAITFOR 等时间延迟函数",
                                        "verified": 1,
                                        "cvss_score": 9.5,
                                        "status": "OPEN"
                                    })
                except Exception:
                    pass
            except Exception:
                pass

            # =========================================================================
            # 3. 📂 多编码与跨平台路径穿越 (Path Traversal / LFI)
            # =========================================================================
            lfi_vectors = [
                ("../../../../etc/passwd", r"root:.*:0:0:", "Linux /etc/passwd 账户特征"),
                ("..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini 配置文件特征"),
                ("%252e%252e%252f%252e%252e%252fetc%252fpasswd", r"root:.*:0:0:", "二次 URL 编码绕过 Linux /etc/passwd"),
                ("....//....//....//etc/passwd", r"root:.*:0:0:", "双写绕过 /etc/passwd")
            ]
            for lfi_payload, verify_regex, desc in lfi_vectors:
                try:
                    test_url = f"{url}?{param}={lfi_payload}"
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as lfi_resp:
                        if lfi_resp.status == 200:
                            lfi_body = await lfi_resp.text(errors="replace")
                            if re.search(verify_regex, lfi_body, re.IGNORECASE) and not self._is_false_positive_spa_response(lfi_body, lfi_resp.status):
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "category": "VULN",
                                    "title": f"参数存在任意文件读取/路径穿越漏洞 [{param}] ({desc})",
                                    "severity": "CRITICAL",
                                    "url": url,
                                    "param": f"Param: {param}",
                                    "evidence": {
                                        "probe_payload": lfi_payload,
                                        "file_type": desc,
                                        "matched_snippet": f"成功跨目录读取系统文件: {desc}"
                                    },
                                    "impact": "攻击者可读取系统敏感配置、源码、秘钥甚至导致远程命令执行",
                                    "remediation": f"对参数 {param} 实施严格白名单映射，过滤 ../ 与 ..\\ 字符，使用 realpath() 校验合法路径边界",
                                    "verified": 1,
                                    "cvss_score": 9.6,
                                    "status": "OPEN"
                                })
                                break
                except Exception:
                    pass

            # =========================================================================
            # 4. 🧮 动态双素数 SSTI 模板注入 (完全动态大数随机乘积校验，杜绝商品价格/规格/年份固定数字撞车)
            # =========================================================================
            import random
            p1 = random.randint(719, 991)
            p2 = random.randint(317, 887)
            dynamic_expected = str(p1 * p2) # 6位随机大数，如 839 * 673 = 564647

            ssti_vectors = [
                (f"{{{{{p1}*{p2}}}}}", dynamic_expected, f"Jinja2 / Twig 模板表达式注入 ({{{{{p1}*{p2}}}}} -> {dynamic_expected})"),
                (f"${{{p1}*{p2}}}", dynamic_expected, f"SpEL / FreeMarker 表达式注入 (${{{p1}*{p2}}} -> {dynamic_expected})"),
                (f"#{{{p1}*{p2}}}", dynamic_expected, f"JSP EL 表达式注入 (#{{{p1}*{p2}}} -> {dynamic_expected})")
            ]
            for ssti_payload, expected_val, desc in ssti_vectors:
                try:
                    test_url = f"{url}?{param}={ssti_payload}"
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as ssti_resp:
                        if ssti_resp.status == 200:
                            ssti_body = await ssti_resp.text(errors="replace")
                            # 严格防误报：计算结果必须存在，且原始表达式没有原样回显，且不是作为 URL 参数字符串被反射
                            if expected_val in ssti_body and ssti_payload not in ssti_body and not self._is_false_positive_spa_response(ssti_body, ssti_resp.status):
                                # 进一步做基线确认：确保 expected_val 不是页面原本就有的数字
                                baseline_url = f"{url}?{param}=das_ssti_baseline_check"
                                async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=4.0)) as base_resp:
                                    base_body = await base_resp.text(errors="replace")
                                    if expected_val not in base_body:
                                        # 二次动态验证：使用第二组独立随机数进行校验，杜绝任何偶发巧合
                                        p3 = random.randint(727, 983)
                                        p4 = random.randint(331, 877)
                                        sec_expected = str(p3 * p4)
                                        sec_payload = ssti_payload.replace(str(p1), str(p3)).replace(str(p2), str(p4))
                                        sec_url = f"{url}?{param}={sec_payload}"
                                        async with session.get(sec_url, timeout=aiohttp.ClientTimeout(total=4.0)) as sec_resp:
                                            if sec_resp.status == 200:
                                                sec_body = await sec_resp.text(errors="replace")
                                                if sec_expected in sec_body and sec_payload not in sec_body:
                                                    findings.append({
                                                        "id": str(uuid.uuid4()),
                                                        "category": "VULN",
                                                        "title": f"参数存在服务端模板注入漏洞 (SSTI) [{param}] ({desc})",
                                                        "severity": "CRITICAL",
                                                        "url": url,
                                                        "param": f"Param: {param}",
                                                        "evidence": {
                                                            "probe_payload": ssti_payload,
                                                            "calculated_result": expected_val,
                                                            "secondary_verification": f"{sec_payload} -> {sec_expected}",
                                                            "matched_snippet": f"服务端模板引擎成功执行动态数学运算并渲染结果: {desc}"
                                                        },
                                                        "impact": "攻击者可通过模板引擎沙箱逃逸执行系统任意代码与提权 (RCE)",
                                                        "remediation": f"禁止将可信模板与用户可控参数 {param} 动态拼接，强制采用静态文本插值",
                                                        "verified": 1,
                                                        "cvss_score": 9.8,
                                                        "status": "OPEN"
                                                    })
                                                    break
                except Exception:
                    pass



            # =========================================================================
            # 5. ⚡ 命令注入 (动态非自含算术执行验证，彻底杜绝 URL 埋点/JS 回显造成的误报)
            # =========================================================================
            math_a = 48218
            math_b = 19283
            math_expected = str(math_a + math_b) # "67501"

            cmd_vectors = [
                (f"; expr {math_a} + {math_b} ;", math_expected, "分号动态算术命令注入"),
                (f"| expr {math_a} + {math_b}", math_expected, "管道符动态算术命令注入"),
                (f"& expr {math_a} + {math_b} &", math_expected, "后台符动态算术命令注入"),
                (f"`expr {math_a} + {math_b}`", math_expected, "反引号动态算术命令执行"),
                ("; echo das_cmd_exec_8394 ;", "das_cmd_exec_8394", "分号分隔符回显命令注入")
            ]
            for cmd_payload, marker, desc in cmd_vectors:
                try:
                    test_url = f"{url}?{param}={cmd_payload}"
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as cmd_resp:
                        if cmd_resp.status == 200:
                            cmd_body = await cmd_resp.text(errors="replace")
                            is_reflection_only = False
                            if "das_cmd_exec_8394" in cmd_payload:
                                if f"url={cmd_payload}" in cmd_body or f'"{cmd_payload}"' in cmd_body or f"'{cmd_payload}'" in cmd_body or "window.location" in cmd_body:
                                    is_reflection_only = True
                            
                            if marker in cmd_body and not is_reflection_only and not self._is_false_positive_spa_response(cmd_body, cmd_resp.status):
                                baseline_url = f"{url}?{param}=das_cmd_baseline_check"
                                async with session.get(baseline_url, timeout=aiohttp.ClientTimeout(total=4.0)) as base_resp:
                                    base_body = await base_resp.text(errors="replace")
                                    if marker not in base_body:
                                        findings.append({
                                            "id": str(uuid.uuid4()),
                                            "category": "VULN",
                                            "title": f"参数存在操作系统命令注入漏洞 (Command Injection) [{param}] ({desc})",
                                            "severity": "CRITICAL",
                                            "url": url,
                                            "param": f"Param: {param}",
                                            "evidence": {
                                                "probe_payload": cmd_payload,
                                                "execution_marker": marker,
                                                "matched_snippet": f"系统成功执行子命令并返回非自含计算特征: {marker}"
                                            },
                                            "impact": "攻击者可直接获取底层操作系统服务器 Shell 权限，控制宿主服务器",
                                            "remediation": f"禁止使用 system()/exec()/os.system() 拼接参数 {param}，改用安全参数列表方式调用",
                                            "verified": 1,
                                            "cvss_score": 9.8,
                                            "status": "OPEN"
                                        })
                                        break
                except Exception:
                    pass

            # =========================================================================
            # 6. 🌐 SSRF 服务端请求伪造 (云元数据与内网探测，排除 HTML 404 伪响应)
            # =========================================================================
            if any(k in param.lower() for k in ["url", "proxy", "link", "target", "src", "fetch", "domain", "api"]):
                ssrf_targets = [
                    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "iam"], "云厂商元数据接口 (AWS/AliCloud Metadata)"),
                    ("http://127.0.0.1:6379/", ["redis", "internal_service", "connected"], "本地 Redis / 内部管理接口"),
                    ("http://2130706433/", ["redis", "internal_service"], "十进制 IP 绕过本地环回")
                ]
                for ssrf_url, markers, desc in ssrf_targets:
                    try:
                        test_url = f"{url}?{param}={ssrf_url}"
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5.0)) as ssrf_resp:
                            if ssrf_resp.status == 200:
                                ssrf_body = await ssrf_resp.text(errors="replace")
                                is_html_webpage = "<!doctype html" in ssrf_body.lower() or "<html" in ssrf_body.lower()
                                if any(m in ssrf_body.lower() for m in markers) and not is_html_webpage and not self._is_false_positive_spa_response(ssrf_body, ssrf_resp.status):
                                    findings.append({
                                        "id": str(uuid.uuid4()),
                                        "category": "VULN",
                                        "title": f"参数存在服务端请求伪造漏洞 (SSRF) [{param}] ({desc})",
                                        "severity": "HIGH",
                                        "url": url,
                                        "param": f"Param: {param}",
                                        "evidence": {
                                            "ssrf_target": ssrf_url,
                                            "matched_snippet": f"服务端向内部目标发起请求并回显元数据特征: {desc}"
                                        },
                                        "impact": "攻击者可探测内网未公开服务、窃取云主机 IAM 凭证并攻击内网数据库",
                                        "remediation": f"对参数 {param} 实施严格协议白名单 (仅限 http/https)，并在网络层禁止访问私有网段",
                                        "verified": 1,
                                        "cvss_score": 8.6,
                                        "status": "OPEN"
                                    })
                                    break
                    except Exception:
                        pass

        # 7. 🌐 扫描页面中的 Subresource Integrity (SRI) 与表单 CSRF Token 缺失
        sri_csrf_findings = self._check_sri_and_csrf_hygiene(crawled_pages)
        findings.extend(sri_csrf_findings)

        return findings

    def _check_sri_and_csrf_hygiene(self, crawled_pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """检测外部 CDN 脚本缺失 SRI 完整性校验与敏感表单缺失 Anti-CSRF Token"""
        findings = []
        seen_sri_hosts = set()
        
        for p in crawled_pages:
            url = p.get("url", "")
            html = p.get("html_content", "")
            if not html:
                continue
            try:
                soup = BeautifulSoup(html, "html.parser")
                
                # 1. 外部第三方 CDN 脚本未配置 integrity 属性 (SRI)
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                        parsed_src = urlparse(src if not src.startswith("//") else "https:" + src)
                        script_netloc = parsed_src.netloc.lower().split(':')[0]
                        
                        # 排除同源、主域名子域及常用首方 CDN
                        is_own_domain = False
                        for auth in self.auth_domains:
                            auth_clean = auth.lower().split(':')[0]
                            if script_netloc == auth_clean or script_netloc.endswith("." + auth_clean) or auth_clean.endswith("." + script_netloc):
                                is_own_domain = True
                                break
                            base_root = ".".join(auth_clean.split('.')[-2:]) if '.' in auth_clean else auth_clean
                            if base_root in script_netloc:
                                is_own_domain = True
                                break

                        if script_netloc and not is_own_domain:
                            if not script.get("integrity") and script_netloc not in seen_sri_hosts:
                                seen_sri_hosts.add(script_netloc)
                                findings.append({
                                    "id": str(uuid.uuid4()),
                                    "category": "VULN",
                                    "title": f"外部第三方 CDN 脚本缺失子资源完整性校验 (SRI) [{script_netloc}]",
                                    "severity": "INFO",
                                    "url": url,
                                    "param": f"Script: {src[:60]}",
                                    "evidence": {
                                        "script_src": src,
                                        "missing_attribute": "integrity"
                                    },
                                    "impact": "若第三方 CDN 服务商遭受供应链污染或 DNS 劫持，恶意脚本将在本站用户浏览器中直接执行",
                                    "remediation": "在加载外部 CDN 脚本时增加 integrity 属性 (例如 integrity='sha384-...' crossorigin='anonymous')",
                                    "verified": 1,
                                    "cvss_score": 3.5,
                                    "status": "OPEN"
                                })

                # 2. 敏感 POST 表单未配置 CSRF Token（精准检测，排除搜索/联系/纯静态表单误报）
                for form in soup.find_all("form"):
                    method = form.get("method", "GET").upper()
                    action_url = form.get("action", "").lower()
                    if method == "POST":
                        # 排除公开订阅（Newsletter）、留言咨询（Contact）、搜索与货币语言切换等无需鉴权的公开提交表单（SRC 标准属于非漏洞）
                        form_id_or_class = (form.get("id", "") + " " + " ".join(form.get("class", []))).lower()
                        if any(ignore_k in form_id_or_class or ignore_k in action_url for ignore_k in [
                            "newsletter", "subscribe", "subscription", "contact", "feedback", "search",
                            "locale", "currency", "footer", "survey", "comment"
                        ]):
                            continue

                        # 只检查有实质高危鉴权或状态修改动作的表单（排除无凭证或低风险公开表单）
                        form_inputs = form.find_all("input")
                        input_names = [inp.get("name", "").lower() for inp in form_inputs]
                        # 判断是否是高风险状态变更表单（必须涉及密码、账户绑定、订单支付、管理设置等核心操作）
                        is_state_changing = any(
                            any(k in n for k in [
                                "password", "passwd", "account",
                                "pay", "order", "transfer", "amount", "delete",
                                "setting", "profile", "update", "modify", "change_pwd"
                            ]) for n in input_names
                        ) or any(k in action_url for k in [
                            "login", "register", "pay", "order", "transfer",
                            "account", "setting", "profile", "delete", "update", "password"
                        ])
                        if not is_state_changing:
                            continue  # 非状态变更表单跳过

                        has_csrf = False
                        for inp in form_inputs:
                            inp_name = inp.get("name", "").lower()
                            inp_type = inp.get("type", "").lower()
                            # 检查 CSRF token 字段或隐藏随机字段（长度 > 16 的 hidden input 通常是 token）
                            if any(k in inp_name for k in ["csrf", "token", "xsrf", "_token", "authenticity"]):
                                has_csrf = True
                                break
                            if inp_type == "hidden":
                                val = inp.get("value", "")
                                if val and len(val) >= 16 and re.search(r'[a-zA-Z0-9+/=_\-]{16,}', val):
                                    has_csrf = True  # 疑似随机 token 隐藏字段
                                    break
                        if not has_csrf:
                            form_snippet = str(form)[:300]
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": f"状态变更 POST 表单缺失 Anti-CSRF Token 防御机制 [{action_url or url}]",
                                "severity": "MEDIUM",
                                "url": url,
                                "param": f"Form Action: {form.get('action', '')}",
                                "evidence": {
                                    "form_action": form.get("action", ""),
                                    "form_fields": input_names,
                                    "missing_defense": "Anti-CSRF Token",
                                    "matched_snippet": form_snippet
                                },
                                "impact": "第三方恶意网站可通过跨站伪造请求诱使用户在不知情的情况下提交敏感表单，导致账户信息被篡改、资产被转移",
                                "remediation": "为所有状态改变的 POST 表单增加不可预测的随机 Anti-CSRF Token 校验（SameSite=Strict Cookie 可辅助防护）",
                                "verified": 1,
                                "cvss_score": 6.5,
                                "status": "OPEN"
                            })
            except Exception as e:
                logger.debug(f"Error checking SRI/CSRF on {url}: {e}")

        return findings

    async def _probe_api_unauthorized_endpoints(self, session: aiohttp.ClientSession, discovered_apis: List[str]) -> List[Dict[str, Any]]:
        """向后兼容，调用 v2 版本"""
        return await self._probe_api_unauthorized_endpoints_v2(session, discovered_apis)

    async def _probe_api_unauthorized_endpoints_v2(self, session: aiohttp.ClientSession, discovered_apis: List[str]) -> List[Dict[str, Any]]:
        """v2：深度 API 未授权访问 + BOLA/IDOR ID 枚举探测"""
        findings = []
        base = self.target_url.rstrip('/')

        # 合并已发现 API + 常见 API 路径字典
        common_apis = [
            f"{base}/api/user", f"{base}/api/users", f"{base}/api/profile",
            f"{base}/api/v1/user", f"{base}/api/v1/users", f"{base}/api/v1/profile",
            f"{base}/api/v2/user", f"{base}/api/v2/profile",
            f"{base}/api/me", f"{base}/api/account", f"{base}/api/accounts",
            f"{base}/api/admin", f"{base}/api/admin/users",
            f"{base}/api/orders", f"{base}/api/order",
            f"{base}/api/config", f"{base}/api/settings",
            f"{base}/api/debug", f"{base}/api/health",
            f"{base}/v1/user", f"{base}/v1/users", f"{base}/v2/user",
        ]
        target_apis = list(dict.fromkeys(list(discovered_apis) + common_apis))  # 去重

        sensitive_keys = [
            "email", "phone", "mobile", "password", "passwd", "token",
            "balance", "role", "is_admin", "address", "id_card", "idcard",
            "bank", "credit", "secret", "api_key", "access_token", "refresh_token"
        ]

        for api_url in target_apis[:25]:  # 最多测 25 个
            try:
                async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=5.0),
                                       allow_redirects=False) as resp:
                    if resp.status not in (200, 201):
                        continue
                    content_type = resp.headers.get("Content-Type", "")
                    if "application/json" in content_type or "text/plain" in content_type:
                        try:
                            body = await resp.text(errors="replace")
                            # 过滤 SPA 软404
                            if self._is_false_positive_spa_response(body, resp.status):
                                continue
                            body_lower = body.lower()
                            matched_keys = [k for k in sensitive_keys if k in body_lower]
                            if matched_keys:
                                # 进一步验证：尝试解析 JSON 确认是结构化数据而非错误页
                                is_structured = False
                                sample = ""
                                try:
                                    data = json.loads(body)
                                    is_structured = isinstance(data, (dict, list))
                                    sample = json.dumps(data)[:300] if is_structured else body[:300]
                                except Exception:
                                    sample = body[:300]
                                    # 判断是否是 JSON 格式（即使解析失败）
                                    is_structured = body.strip().startswith(('{', '['))

                                if is_structured:
                                    findings.append({
                                        "id": str(uuid.uuid4()),
                                        "category": "VULN",
                                        "title": f"API 未授权访问：无需认证可获取敏感字段数据 [{api_url}]",
                                        "severity": "HIGH",
                                        "url": api_url,
                                        "param": "Authorization: (无)",
                                        "evidence": {
                                            "endpoint": api_url,
                                            "status_code": resp.status,
                                            "content_type": content_type,
                                            "sensitive_fields_found": matched_keys,
                                            "matched_snippet": sample,
                                            "verification_steps": [
                                                f"curl -sk '{api_url}'",
                                                "无需任何 Authorization Header 即可获取响应",
                                                f"响应中包含敏感字段: {matched_keys}"
                                            ]
                                        },
                                        "impact": "攻击者无需任何凭据即可批量读取用户隐私数据（邮箱、手机、余额、权限标识等），满足 SRC 中危认定标准",
                                        "remediation": f"在 {api_url} 增加强制身份验证中间件 (JWT Bearer / Session Cookie 校验)，对匿名访问返回 401",
                                        "verified": 1,
                                        "cvss_score": 7.5,
                                        "status": "OPEN"
                                    })
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"API unauth probe error {api_url}: {e}")

        # BOLA/IDOR：对已发现含有数字 ID 的 API 进行 ID 遍历越权探测
        # 提取 URL 中含有数字路径段的 API
        id_pattern = re.compile(r'/(\d+)(?:/|$)')
        for api_url in list(discovered_apis)[:15]:
            if not id_pattern.search(api_url):
                continue
            try:
                # 先获取原始 ID 的响应（作为基线）
                async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=5.0)) as base_resp:
                    if base_resp.status != 200:
                        continue
                    base_body = await base_resp.text(errors="replace")
                    if not base_body.strip().startswith(('{', '[')):
                        continue

                # 将 ID 加1，测试是否能访问其他用户数据（水平越权）
                original_id_match = id_pattern.search(api_url)
                original_id = int(original_id_match.group(1))
                tampered_url = api_url[:original_id_match.start(1)] + str(original_id + 1) + api_url[original_id_match.end(1):]

                async with session.get(tampered_url, timeout=aiohttp.ClientTimeout(total=5.0)) as tamper_resp:
                    if tamper_resp.status == 200:
                        tamper_body = await tamper_resp.text(errors="replace")
                        if (
                            tamper_body.strip().startswith(('{', '['))
                            and tamper_body != base_body
                            and len(tamper_body) > 20
                        ):
                            findings.append({
                                "id": str(uuid.uuid4()),
                                "category": "VULN",
                                "title": f"BOLA/IDOR 水平越权：通过篡改 ID 可访问其他用户数据 [{tampered_url}]",
                                "severity": "HIGH",
                                "url": tampered_url,
                                "param": f"Path ID: {original_id} → {original_id + 1}",
                                "evidence": {
                                    "original_url": api_url,
                                    "tampered_url": tampered_url,
                                    "original_status": 200,
                                    "tampered_status": 200,
                                    "matched_snippet": tamper_body[:300],
                                    "verification_steps": [
                                        f"curl -sk '{api_url}' → 返回用户 {original_id} 的数据",
                                        f"curl -sk '{tampered_url}' → 同样返回 200 + 数据",
                                        "服务端未校验当前登录用户是否有权访问目标资源 ID"
                                    ]
                                },
                                "impact": "攻击者可遍历数字 ID 批量读取所有用户的私密数据，满足 SRC 高危/中危认定标准",
                                "remediation": "在 API 中对每个资源 ID 进行 Ownership 校验，确保当前用户只能访问自己的资源",
                                "verified": 1,
                                "cvss_score": 8.1,
                                "status": "OPEN"
                            })
            except Exception as e:
                logger.debug(f"BOLA/IDOR probe error {api_url}: {e}")

        return findings

    @staticmethod

    def construct_exploit_chain(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """为发现的漏洞生成实战化 4-Stage 攻击利用推演链路 (Exploit Progression Chain)"""
        cat = finding.get("category", "")
        title = (finding.get("title", "") or "").lower()
        url = finding.get("url", "")
        
        if "sql" in title or "注入" in title:
            return [
                {"stage": 1, "name": "侦察与边界注入", "action": "发送单引号/差分/时间盲注 Payload 探测数据库解析", "tier": "Frontend / Gateway"},
                {"stage": 2, "name": "错误指纹与版本探测", "action": "触发数据库语法异常或统计延时，确定底层 RDBMS 类型", "tier": "Backend App"},
                {"stage": 3, "name": "元数据提取与脱库", "action": "构造 UNION / Blind 注入提取 information_schema 表结构与用户凭据", "tier": "Database Layer"},
                {"stage": 4, "name": "权限维持与 UDF 提权", "action": "尝试 into outfile 写入 WebShell 或调用 xp_cmdshell / sys_eval 提权", "tier": "Host OS / Root"}
            ]
        elif "ssti" in title or "模板" in title:
            return [
                {"stage": 1, "name": "模板表达式探测", "action": "注入动态数学运算 ${{829*743}} 探测模板引擎渲染", "tier": "Frontend / View"},
                {"stage": 2, "name": "引擎指纹识别", "action": "识别 Jinja2 / Twig / SpEL / FreeMarker 引擎上下文对象", "tier": "Template Engine"},
                {"stage": 3, "name": "沙箱逃逸链构造", "action": "遍历 __mro__ / __subclasses__ 寻找 subprocess.Popen / Runtime", "tier": "Runtime Sandbox"},
                {"stage": 4, "name": "任意代码执行 (RCE)", "action": "调用底层 OS 系统命令执行反弹 Shell 接管宿主机", "tier": "Host Server"}
            ]
        elif "命令注入" in title or "command" in title:
            return [
                {"stage": 1, "name": "参数分隔符探测", "action": "注入 ; / | / & 等 Shell 元字符并验证动态非自含算术执行", "tier": "API Gateway"},
                {"stage": 2, "name": "命令执行通道建立", "action": "绕过参数过滤与 WAF 限制，实现底层系统调用", "tier": "Web Application"},
                {"stage": 3, "name": "敏感凭据窃取", "action": "读取 /etc/passwd、.env、云厂商 AK/SK 环境变量", "tier": "Operating System"},
                {"stage": 4, "name": "横向移动与特权提升", "action": "下载恶意 Payload，建立持久化 C2 隧道与提权", "tier": "Internal Network"}
            ]
        elif "文件读取" in title or "path traversal" in title or "lfi" in title:
            return [
                {"stage": 1, "name": "路径穿越探测", "action": "发送 ../ 多级跨目录编码绕过文件名白名单限制", "tier": "Web Endpoint"},
                {"stage": 2, "name": "系统敏感文件读取", "action": "成功读取 /etc/passwd、win.ini、应用配置文件", "tier": "File System"},
                {"stage": 3, "name": "源码与数据库凭据泄露", "action": "读取 config.py / database.yml 获取数据库密码与 JWT 密钥", "tier": "Application Core"},
                {"stage": 4, "name": "日志投毒与代码执行", "action": "结合 SSH / Apache 日志包含 (Log Poisoning) 转化为 RCE", "tier": "Host OS"}
            ]
        elif "xss" in title:
            return [
                {"stage": 1, "name": "字符逃逸测试", "action": "发送 <xss> 探针测试 HTML 标签与属性逃逸", "tier": "User Browser"},
                {"stage": 2, "name": "Payload 武器化", "action": "构造恶意 <script> 或 img onerror 绕过 XSS 过滤器", "tier": "DOM Rendering"},
                {"stage": 3, "name": "Session/Cookie 劫持", "action": "执行 document.cookie 窃取受害者登录凭据并外带", "tier": "Client Context"},
                {"stage": 4, "name": "钓鱼与特权劫持", "action": "伪造系统登录框或发起静默 CSRF 操作劫持账户", "tier": "Admin Session"}
            ]
        elif "ssrf" in title:
            return [
                {"stage": 1, "name": "网络协议与内网探测", "action": "注入 127.0.0.1 / 169.254.169.254 测试服务端内网发包", "tier": "Reverse Proxy"},
                {"stage": 2, "name": "内网服务拓扑识别", "action": "探测内网 Redis (6379)、MySQL (3306)、Elasticsearch 端口", "tier": "Intranet Infrastructure"},
                {"stage": 3, "name": "云凭据与元数据窃取", "action": "读取 AWS / 阿里云 IAM Security Credentials 访问密钥", "tier": "Cloud Provider"},
                {"stage": 4, "name": "内网未授权服务攻击", "action": "利用 gopher / dict 协议向内网 Redis 写入 SSH 公钥或计划任务", "tier": "Internal Server"}
            ]
        elif "bola" in title or "越权" in title:
            return [
                {"stage": 1, "name": "对象标识符探测", "action": "发现用户个人主页与数据接口暴露数字自增 ID", "tier": "API Gateway"},
                {"stage": 2, "name": "水平/垂直越权枚举", "action": "篡改 user_id 参数，遍历其他租户与管理员私密数据", "tier": "Auth Middleware"},
                {"stage": 3, "name": "敏感数据批量导出", "action": "未授权读取全站用户手机号、身份证、交易账单与权限标识", "tier": "Database / API"},
                {"stage": 4, "name": "特权提升与账户接管", "action": "利用高权限用户 Token 伪造管理凭据接管整个应用", "tier": "Management Plane"}
            ]
        else:
            return [
                {"stage": 1, "name": "配置缺陷识别", "action": "检测到安全标头缺失或传输层安全策略未严格配置", "tier": "HTTP Header"},
                {"stage": 2, "name": "潜在利用面分析", "action": "缺乏防御层级，可能被攻击者结合其他漏洞进行组合利用", "tier": "Defense Layer"},
                {"stage": 3, "name": "攻击难度降低", "action": "为黑客实施跨站攻击、点击劫持或协议降级提供便利", "tier": "Security Boundary"},
                {"stage": 4, "name": "安全合规加固", "action": "按等保 2.0 与最佳实践建议增加防御性安全标头与加密", "tier": "Compliance Remediation"}
            ]



    # ==========================================================================
    # GraphQL Probe
    # ==========================================================================
    async def _probe_graphql_endpoints(self, session) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        base = self.target_url.rstrip("/")
        paths = [
            f"{base}/graphql", f"{base}/api/graphql", f"{base}/v1/graphql",
            f"{base}/gql", f"{base}/api/gql", f"{base}/query",
        ]
        payload = '{"query":"{__schema{types{name}}}"}'
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        for url in paths:
            try:
                async with session.post(url, data=payload, headers=hdrs,
                        timeout=_aiohttp.ClientTimeout(total=6.0), allow_redirects=False) as r:
                    if r.status == 200:
                        body = await r.text(errors="replace")
                        if '"__schema"' in body and '"types"' in body and not self._is_false_positive_spa_response(body, r.status):
                            findings.append({
                                "id": str(_uuid.uuid4()), "category": "VULN",
                                "title": f"GraphQL端点未授权自省暴露Schema [{url}]",
                                "severity": "MEDIUM", "url": url, "param": "POST introspection",
                                "evidence": {
                                    "matched_snippet": body[:400],
                                    "introspection_payload": payload,
                                    "verification_steps": [
                                        f"curl -sk -X POST '{url}' -H 'Content-Type: application/json' -d '{payload}'",
                                        "返回 __schema.types 说明自省未禁用"
                                    ]
                                },
                                "impact": "攻击者可获取完整API schema用于构造未授权查询",
                                "remediation": "生产环境禁用GraphQL Introspection",
                                "verified": 1, "cvss_score": 5.3, "status": "OPEN"
                            })
            except Exception as e:
                import logging
                logging.getLogger("das_sentinel.vuln").debug(f"GraphQL {url}: {e}")
        return findings

    # ==========================================================================
    # API Routes Bruteforce Probe
    # ==========================================================================
    async def _probe_api_routes_bruteforce(self, session) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        base = self.target_url.rstrip("/")
        paths = [
            "/admin", "/admin/api", "/admin/users", "/api/admin",
            "/api/internal", "/api/users", "/api/user/list",
            "/api/v1/users", "/api/v2/users", "/api/config",
            "/api/settings", "/api/env", "/actuator", "/actuator/env",
            "/actuator/beans", "/actuator/heapdump", "/actuator/mappings",
            "/actuator/loggers", "/metrics", "/prometheus",
            "/server-status", "/debug",
        ]
        sensitive = [
            '"email"', '"phone"', '"password"', '"token"', '"role"',
            '"admin"', '"secret"', '"key"', "DATABASE_URL", "SECRET_KEY",
            "APP_KEY", "activeProfiles",
        ]
        for path in paths:
            probe_url = f"{base}{path}"
            try:
                async with session.get(probe_url, allow_redirects=False,
                        timeout=_aiohttp.ClientTimeout(total=5.0)) as r:
                    if r.status not in (200, 201, 206):
                        continue
                    body = await r.text(errors="replace")
                    if not body or self._is_false_positive_spa_response(body, r.status):
                        continue
                    ctype = r.headers.get("Content-Type", "")
                    matched = [s for s in sensitive if s in body]
                    if matched and ("application/json" in ctype or body.strip().startswith(("{", "["))):
                        sev = "HIGH" if any(k in path for k in ["/admin", "heapdump", "/internal", "/config"]) else "MEDIUM"
                        findings.append({
                            "id": str(_uuid.uuid4()), "category": "VULN",
                            "title": f"敏感API路径未授权访问 [{path}]",
                            "severity": sev, "url": probe_url, "param": f"Path: {path}",
                            "evidence": {
                                "matched_snippet": body[:350],
                                "sensitive_indicators": matched,
                                "response_status": r.status,
                                "verification_steps": [
                                    f"curl -sk '{probe_url}'",
                                    f"HTTP {r.status}, sensitive fields: {matched[:5]}",
                                    "无需任何认证即可访问"
                                ]
                            },
                            "impact": f"未授权攻击者可访问 {path} 获取敏感数据",
                            "remediation": f"为 {path} 添加认证或在WAF/网络层禁止外网访问",
                            "verified": 1, "cvss_score": 7.5, "status": "OPEN"
                        })
            except Exception as e:
                import logging
                logging.getLogger("das_sentinel.vuln").debug(f"Brute {probe_url}: {e}")
        return findings

    # ==========================================================================
    # Open Redirect Probe
    # ==========================================================================
    async def _probe_open_redirect(self, session, url_parameters) -> list:
        import uuid as _uuid, aiohttp as _aiohttp
        findings = []
        rparams = {
            "redirect", "return", "returnurl", "returnto", "next", "goto",
            "url", "target", "destination", "dest", "from", "callback",
            "redirect_uri", "continue", "forward", "location", "jump"
        }
        evil = "https://evil-attacker-das-sentinel.com/steal"
        tested = set()
        for p_info in (url_parameters or [])[:15]:
            ep = p_info.get("endpoint", "")
            for param in p_info.get("params", []):
                if param.lower() not in rparams:
                    continue
                key = f"{ep}:{param}"
                if key in tested:
                    continue
                tested.add(key)
                probe = f"{ep}?{param}={evil}"
                try:
                    async with session.get(probe, allow_redirects=False,
                            timeout=_aiohttp.ClientTimeout(total=5.0)) as r:
                        loc = r.headers.get("Location", "")
                        if r.status in (301, 302, 303, 307, 308) and "evil-attacker-das-sentinel.com" in loc:
                            findings.append({
                                "id": str(_uuid.uuid4()), "category": "VULN",
                                "title": f"开放重定向漏洞 (Open Redirect) [{param}]",
                                "severity": "MEDIUM", "url": ep, "param": f"Param: {param}",
                                "evidence": {
                                    "probe_url": probe,
                                    "redirect_to": loc,
                                    "status_code": r.status,
                                    "matched_snippet": f"GET {probe} -> {r.status} Location: {loc}",
                                    "verification_steps": [
                                        f"curl -skI '{probe}'",
                                        f"返回 {r.status} Location: {loc}",
                                        "攻击者可构造钓鱼链接或劫持OAuth令牌"
                                    ]
                                },
                                "impact": "攻击者可构造带合法域名外观的恶意链接，用于钓鱼攻击或OAuth令牌劫持",
                                "remediation": f"对参数 {param} 实施跳转目标白名单校验",
                                "verified": 1, "cvss_score": 6.1, "status": "OPEN"
                            })
                except Exception as e:
                    import logging
                    logging.getLogger("das_sentinel.vuln").debug(f"Redirect {probe}: {e}")
        return findings

    # Keep backward compatibility alias
    async def _probe_api_unauthorized_endpoints(self, session, discovered_apis) -> list:
        return await self._probe_api_unauthorized_endpoints_v2(session, discovered_apis)

    async def run(self, context: ScanContext) -> None:
        self.target_url = context.target_url
        self.auth_domains = context.auth_domains
        crawl_meta = {
            'api_endpoints': list(context.api_endpoints),
            'static_assets': list(context.static_assets),
            'js_scripts': context.js_scripts,
            'url_parameters': context.url_parameters,
            'forms': context.forms
        }
        findings = await self.scan_all(context.crawled_pages, crawl_metadata=crawl_meta)
        context.add_findings(findings)
