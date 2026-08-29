from plugins.core.base import BaseScanner, ScanContext
import asyncio
import hashlib
import logging
import re
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
from typing import Set, List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
from backend.app.config import settings

logger = logging.getLogger("das_sentinel.crawler")

class AssetCrawler(BaseScanner):
    """现代 Web 资产拓扑、页面、表单、动态参数与接口深度发现引擎"""

    def __init__(
        self,
        base_url: str,
        auth_domains: List[str],
        max_depth: int = 3,
        max_pages: int = 100,
        qps_limit: float = 5.0,
        timeout_sec: float = 10.0
    ):
        self.base_url = base_url.strip()
        parsed = urlparse(self.base_url)
        self.base_domain = parsed.netloc.split(':')[0]
        self.auth_domains = set(d.strip().lower() for d in auth_domains if d.strip())
        if self.base_domain.lower() not in self.auth_domains:
            self.auth_domains.add(self.base_domain.lower())
            
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = 1.0 / max(qps_limit, 0.5)
        self.timeout = aiohttp.ClientTimeout(total=timeout_sec)
        
        self.visited_urls: Set[str] = set()
        self.pages_data: List[Dict[str, Any]] = []
        self.external_links: Set[str] = set()
        self.static_assets: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_parameters: Dict[str, Set[str]] = {}  # { url_path: set(param_names) }
        self.js_scripts_data: List[Dict[str, Any]] = []      # [ { "url": js_url, "content": js_text } ]
        self.visited_url_structures: Set[str] = set()        # 用于参数去重，例如 /api?id=x 归一化后记录

    def is_authorized(self, url: str) -> bool:
        """严格边界检查：判断目标 URL 是否在授权域名范围内"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or parsed.scheme not in ('http', 'https'):
                return False
            host = parsed.netloc.split(':')[0].lower()
            for auth in self.auth_domains:
                if host == auth or host.endswith("." + auth):
                    return True
            return False
        except Exception:
            return False

    def clean_url(self, url: str) -> str:
        url, _ = urldefrag(url)
        return url.strip()

    def _get_url_structure(self, url: str) -> str:
        """获取归一化的 URL 结构 (例如将 /page?id=123 转化为 /page?id=TYPE_INT) 防止参数轰炸导致无限遍历"""
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if not parsed.query:
                return base
            
            params = parse_qs(parsed.query, keep_blank_values=True)
            normalized_params = []
            for k in sorted(params.keys()):
                normalized_params.append(f"{k}=VAL")
            return f"{base}?{'&'.join(normalized_params)}"
        except Exception:
            return url

    def _extract_url_params(self, url: str):
        """提取并记录 URL 中的查询参数名"""
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if path_key not in self.discovered_parameters:
                    self.discovered_parameters[path_key] = set()
                for p_name in params.keys():
                    self.discovered_parameters[path_key].add(p_name)
        except Exception:
            pass

    async def _fetch_robots_and_sitemap(self, session: aiohttp.ClientSession, queue: List[tuple]):
        """探测 robots.txt 与 sitemap.xml 提取隐藏路由与管理员路径"""
        parsed = urlparse(self.base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # 1. robots.txt
        robots_url = urljoin(root_url, "/robots.txt")
        try:
            async with session.get(robots_url, allow_redirects=True) as resp:
                if resp.status == 200:
                    text = await resp.text(errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                route = parts[1].strip()
                                if route and not route.startswith("#") and "*" not in route:
                                    full_route_url = self.clean_url(urljoin(root_url, route))
                                    if self.is_authorized(full_route_url) and full_route_url not in self.visited_urls:
                                        self.visited_urls.add(full_route_url)
                                        queue.append((full_route_url, 1))
        except Exception as e:
            logger.debug(f"robots.txt check failed for {root_url}: {e}")

        # 2. sitemap.xml (also try sitemap_index.xml)
        for sitemap_path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"]:
            sitemap_url = urljoin(root_url, sitemap_path)
            try:
                async with session.get(sitemap_url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        text = await resp.text(errors="replace")
                        locs = re.findall(r"<loc>(.*?)</loc>", text, re.IGNORECASE)
                        for loc in locs[:30]:
                            loc_clean = self.clean_url(loc.strip())
                            loc_struct = self._get_url_structure(loc_clean)
                            if self.is_authorized(loc_clean) and loc_struct not in self.visited_url_structures:
                                self.visited_urls.add(loc_clean)
                                self.visited_url_structures.add(loc_struct)
                                queue.append((loc_clean, 1))
            except Exception as e:
                logger.debug(f"{sitemap_path} check failed for {root_url}: {e}")

        # 3. API 接口文档探测 (Swagger / OpenAPI / GraphQL)
        api_doc_paths = [
            "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
            "/openapi.json", "/api/openapi.json", "/v2/api-docs",
            "/.well-known/openapi", "/doc.json", "/api/doc",
        ]
        for doc_path in api_doc_paths:
            doc_url = urljoin(root_url, doc_path)
            try:
                async with session.get(doc_url, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=5.0)) as resp:
                    if resp.status == 200:
                        ctype = resp.headers.get("Content-Type", "")
                        if "json" in ctype or "yaml" in ctype:
                            doc_text = await resp.text(errors="replace")
                            # Extract paths from OpenAPI spec
                            api_paths = re.findall(r'"(/(?:api|v\d+|auth|user|admin|order|product)[^"]{0,80})"', doc_text)
                            for ap in api_paths[:50]:
                                full_ap = urljoin(root_url, ap)
                                if self.is_authorized(full_ap):
                                    self.api_endpoints.add(full_ap)
                            logger.info(f"Found API doc at {doc_url}, extracted {len(api_paths)} endpoints")
            except Exception:
                pass

    async def crawl(self, progress_callback=None) -> Dict[str, Any]:
        """执行异步广度优先（BFS）网站页面与资源发现"""
        queue = [(self.base_url, 1)]
        self.visited_urls.add(self.clean_url(self.base_url))
        self.visited_url_structures.add(self._get_url_structure(self.base_url))
        self._extract_url_params(self.base_url)
        
        headers = {
            "User-Agent": settings.DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"
        }
        
        connector = aiohttp.TCPConnector(ssl=False, limit=settings.DEFAULT_CONCURRENCY)
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=self.timeout, trust_env=True) as session:
            # 优先从 robots.txt / sitemap.xml 注入初始发现
            await self._fetch_robots_and_sitemap(session, queue)

            while queue and len(self.pages_data) < self.max_pages:
                current_url, depth = queue.pop(0)
                
                # 限速与合规控制
                await asyncio.sleep(self.delay)
                
                try:
                    logger.info(f"Crawling [Depth {depth}]: {current_url}")
                    async with session.get(current_url, allow_redirects=True) as resp:
                        content_type = resp.headers.get("Content-Type", "")
                        status_code = resp.status
                        
                        # 记录 Set-Cookie 标头
                        resp_headers = dict(resp.headers)
                        raw_cookies = resp.headers.getall("Set-Cookie", []) if hasattr(resp.headers, "getall") else []
                        
                        # 仅抓取 HTML/文本或 JSON
                        if "text/html" in content_type or "application/xhtml+xml" in content_type:
                            html_text = await resp.text(errors="replace")
                            soup = BeautifulSoup(html_text, "html.parser")
                            
                            # 计算内容与 DOM 指纹 Hash
                            dom_hash = hashlib.sha256(soup.get_text().encode("utf-8")).hexdigest()
                            
                            # 提取标题
                            title_tag = soup.find("title")
                            title = title_tag.get_text().strip() if title_tag else current_url
                            
                            page_record = {
                                "url": str(resp.url),
                                "status": status_code,
                                "title": title,
                                "content_type": content_type,
                                "html_content": html_text,
                                "dom_hash": dom_hash,
                                "headers": resp_headers,
                                "cookies": raw_cookies,
                                "depth": depth
                            }
                            self.pages_data.append(page_record)
                            
                            if progress_callback:
                                await progress_callback(len(self.pages_data), self.max_pages, f"已发现页面: {title[:20]} ({current_url})")

                            # 提取表单 (Forms)
                            for form in soup.find_all("form"):
                                form_action = self.clean_url(urljoin(str(resp.url), form.get("action", "")))
                                form_method = form.get("method", "GET").upper()
                                form_inputs = []
                                for inp in form.find_all(["input", "textarea", "select"]):
                                    name = inp.get("name")
                                    if name:
                                        form_inputs.append({"name": name, "type": inp.get("type", "text")})
                                self.discovered_forms.append({
                                    "page_url": str(resp.url),
                                    "action": form_action,
                                    "method": form_method,
                                    "inputs": form_inputs
                                })

                            # 发现子链接与资源
                            if depth < self.max_depth and len(self.pages_data) < self.max_pages:
                                # a 标签超链接
                                for a_tag in soup.find_all("a", href=True):
                                    raw_href = a_tag["href"]
                                    full_url = self.clean_url(urljoin(str(resp.url), raw_href))
                                    if full_url.startswith("http://") or full_url.startswith("https://"):
                                        self._extract_url_params(full_url)
                                        if self.is_authorized(full_url):
                                            url_struct = self._get_url_structure(full_url)
                                            if url_struct not in self.visited_url_structures:
                                                self.visited_urls.add(full_url)
                                                self.visited_url_structures.add(url_struct)
                                                queue.append((full_url, depth + 1))
                                        else:
                                            self.external_links.add(full_url)
                                            
                                # 静态资源与文件
                                for tag, attr in [("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src")]:
                                    for elem in soup.find_all(tag, **{attr: True}):
                                        res_url = self.clean_url(urljoin(str(resp.url), elem[attr]))
                                        if res_url.startswith("http://") or res_url.startswith("https://"):
                                            self.static_assets.add(res_url)
                                            # 收集 JS 文件以便后续深层代码与 SourceMap 审计
                                            if res_url.endswith(".js") or ".js?" in res_url:
                                                if self.is_authorized(res_url) and len(self.js_scripts_data) < 25:
                                                    try:
                                                        async with session.get(res_url, timeout=aiohttp.ClientTimeout(total=5.0)) as js_resp:
                                                            if js_resp.status == 200:
                                                                js_text = await js_resp.text(errors="replace")
                                                                self.js_scripts_data.append({"url": res_url, "content": js_text})
                                                                # 自动提取 Webpack / Axios / Fetch / vue-router 中的 API 路由 (增强正则)
                                                                api_patterns = [
                                                                    r"['\"]\s*(/(?:api|v[1-9]|auth|user|admin|service|gateway|backend|portal|graphql|graphql-api)/[a-zA-Z0-9_/{}.-]{2,100})['\"]\s*[,\)\}\]]?",
                                                                    r"(?:baseURL|apiUrl|apiBase|baseApi|API_BASE|api_base)\s*[:=]\s*['\"]([^'\"]{5,120})['\"]",
                                                                    r"fetch\s*\(\s*['\"]([^'\"]{5,150})['\"]",
                                                                    r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*['\"]([^'\"]{5,150})['\"]",
                                                                    r"\$http\.(?:get|post|put|delete)\s*\(\s*['\"]([^'\"]{5,150})['\"]",
                                                                    r"url\s*:\s*['\"](/(?:api|v\d+)/[^'\"]+)['\"]", 
                                                                    r"endpoint\s*:\s*['\"]([^'\"]+)['\"]"
                                                                ]
                                                                for pat in api_patterns:
                                                                    for m in re.findall(pat, js_text):
                                                                        if isinstance(m, str) and len(m) > 3:
                                                                            if m.startswith('/'):
                                                                                full_api = urljoin(self.base_url, m)
                                                                            elif m.startswith('http'):
                                                                                full_api = m
                                                                            else:
                                                                                continue
                                                                            if self.is_authorized(full_api):
                                                                                self.api_endpoints.add(full_api)
                                                    except Exception:
                                                        pass
                                            # 检测是否是 API
                                            if "/api/" in res_url or "/v1/" in res_url or "/v2/" in res_url:
                                                self.api_endpoints.add(res_url)


                        elif "application/json" in content_type or "text/plain" in content_type:
                            body_text = await resp.text(errors="replace")
                            dom_hash = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
                            self.pages_data.append({
                                "url": str(resp.url),
                                "status": status_code,
                                "title": "API/Plain Endpoint",
                                "content_type": content_type,
                                "html_content": body_text,
                                "dom_hash": dom_hash,
                                "headers": resp_headers,
                                "cookies": raw_cookies,
                                "depth": depth
                            })
                            self.api_endpoints.add(str(resp.url))

                except Exception as e:
                    logger.warning(f"Error crawling {current_url}: {e}")
                    
        # 整理参数格式
        structured_params = []
        for endpoint, p_set in self.discovered_parameters.items():
            structured_params.append({"endpoint": endpoint, "params": list(p_set)})

        return {
            "target_url": self.base_url,
            "total_pages": len(self.pages_data),
            "pages": self.pages_data,
            "external_links": list(self.external_links),
            "static_assets": list(self.static_assets),
            "api_endpoints": list(self.api_endpoints),
            "forms": self.discovered_forms,
            "url_parameters": structured_params,
            "js_scripts": self.js_scripts_data
        }

    async def run(self, context: ScanContext) -> None:
        self.base_url = context.target_url
        self.auth_domains = context.auth_domains
        self.max_depth = context.scan_scope.get('max_depth', 3)
        self.max_pages = context.scan_scope.get('max_pages', 50)
        self.qps_limit = context.scan_scope.get('qps_limit', 5.0)
        results = await self.crawl()
        context.crawled_pages = results.get('pages', [])
        context.external_links = results.get('external_links', [])
        context.js_scripts = results.get('js_scripts', [])
        context.static_assets = set(results.get('static_assets', []))
        context.api_endpoints = set(results.get('api_endpoints', []))
        context.url_parameters = results.get('url_parameters', [])
        context.forms = results.get('forms', [])
