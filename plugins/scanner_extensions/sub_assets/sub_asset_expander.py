import asyncio
import logging
import re
import socket
import ssl
from typing import Dict, Any, List, Set, Optional, Tuple
from urllib.parse import urlparse
import aiohttp

from backend.app.config import settings
from plugins.core.scope_manager import SRCScopingEngine
from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.sub_asset_expander")

HIGH_VALUE_SUBDOMAIN_WORDLIST = [
    "sso", "auth", "login", "passport", "cas", "oauth", "iam", "gateway", "gw", "api-gw", "jwt", "token", "sso-test", "sso-dev", "vpn",
    "api", "open", "rest", "v1", "v2", "v3", "service", "services", "backend", "app", "mobile", "m", "graphql", "ws", "wss", "rpc", "grpc", "soa",
    "admin", "manage", "oa", "portal", "dashboard", "console", "crm", "erp", "ops", "monitor", "sys", "sysadmin", "boss",
    "grafana", "zabbix", "prometheus", "jenkins", "git", "gitlab", "jira", "wiki", "confluence", "sonar", "nexus", "argocd", "harbor", "kibana", "elk", "splunk",
    "dev", "test", "stage", "staging", "uat", "qa", "sit", "beta", "pre", "demo", "sandbox", "test1", "test2", "local", "dev1",
    "cdn", "static", "img", "images", "res", "assets", "oss", "cos", "files", "download", "s3", "minio", "video", "media", "upload", "ftp",
    "mail", "email", "smtp", "status", "docs", "pay", "payment", "cloud", "db", "mysql", "redis", "k8s", "docker", "registry", "owa", "exchange", "hr", "salary"
]

CDN_CNAME_PATTERNS = {
    "Cloudflare": ["cloudflare.net", "cloudflare.com", "cdn.cloudflare.net"],
    "Akamai": ["akamai.net", "akamaiedge.net", "edgekey.net", "edgesuite.net"],
    "Aliyun CDN / WAF": ["kunlun", "alikunlun", "aliyunwaf", "alicloud", "alicdn", "yundun"],
    "Tencent Cloud CDN": ["dnsv1.com", "qcloudcdn", "cdntip.com", "myqcloud.com"]
}

TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {"cnames": ["github.io"], "body": "There isn't a GitHub Pages site here", "status": [404]},
    "AWS S3 Bucket": {"cnames": ["s3.amazonaws.com", "s3-website"], "body": "The specified bucket does not exist", "status": [404]},
    "Heroku": {"cnames": ["herokudns.com", "herokuapp.com"], "body": "No such app", "status": [404, 502]},
    "Shopify": {"cnames": ["myshopify.com"], "body": "Sorry, this shop is currently unavailable", "status": [404]}
}

class SubAssetExpander(BaseScanner):
    """
    横向子资产与多源旁站测绘引擎 (Subdomain & Lateral Attack Surface Expander)
    方向：sub_assets
    职责：
    1. 被动内容提取 (HTML/JS/CSP/外链正则)
    2. 主动字典爆破与证书透明度 (crt.sh)
    3. CNAME 悬挂与子域名接管 (Subdomain Takeover) 检测
    4. 资产角色分类与拓扑聚合
    """

    def __init__(self, target_url: str = "", auth_domains: List[str] = None, *args, **kwargs):
        super().__init__()
        self.target_url = target_url
        self.auth_domains = auth_domains or []
        if target_url:
            parsed = urlparse(target_url)
            self.target_host = parsed.netloc.split(":")[0].lower()
            self.target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            self.target_scheme = parsed.scheme or "http"
            self.root_domain = self._extract_root_domain(self.target_host)
        else:
            self.target_host = ""
            self.target_port = 80
            self.target_scheme = "http"
            self.root_domain = ""

        self.scope_manager = SRCScopingEngine(auth_domains=self.auth_domains)
        self.max_concurrency = 15
        self.discovered_subdomains: Set[str] = set()
        self.sub_assets_data: List[Dict[str, Any]] = []
        self.risk_findings: List[Dict[str, Any]] = []
        self.catch_all_fingerprints: List[Dict[str, Any]] = []
        self.enable_external_sources = False

    def _extract_root_domain(self, host: str) -> str:
        if not host:
            return ""
        host_lower = host.lower().strip()
        # IP 地址直接返回
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host_lower):
            return host_lower
        parts = host_lower.split(".")
        if len(parts) >= 3 and (parts[-2] in ["com", "gov", "org", "edu", "net", "ac", "sh", "bj", "zj"] and len(parts[-1]) <= 3):
            return ".".join(parts[-3:])
        elif len(parts) >= 2:
            return ".".join(parts[-2:])
        return host_lower

    def passive_extract_from_crawled_content(self, pages_data: List[Dict[str, Any]], js_scripts: List[Dict[str, Any]] = None, external_links: List[str] = None) -> Set[str]:
        found = set()
        root = self.root_domain
        if not root:
            return found

        pattern = re.compile(rf"([a-zA-Z0-9][-a-zA-Z0-9]*\.)+{re.escape(root)}", re.IGNORECASE)
        
        # 扫描 HTML
        for p in (pages_data or []):
            content = p.get("html_content") or p.get("html") or ""
            for m in pattern.finditer(content):
                found.add(m.group(0).lower())
            # CSP 标头
            headers = p.get("headers") or {}
            csp = headers.get("Content-Security-Policy", "")
            for m in pattern.finditer(csp):
                found.add(m.group(0).lower())

        # 扫描 JS
        for j in (js_scripts or []):
            content = j.get("content", "")
            for m in pattern.finditer(content):
                found.add(m.group(0).lower())

        # 扫描外链
        for ext in (external_links or []):
            try:
                parsed = urlparse(ext)
                host = parsed.netloc.split(":")[0].lower()
                if host.endswith(root):
                    found.add(host)
            except Exception:
                pass

        return found

    def _classify_sub_asset_role(self, hostname: str, title: str = "") -> Dict[str, Any]:
        h = hostname.lower()
        t = (title or "").lower()

        if any(k in h for k in ["sso", "auth", "login", "passport", "cas", "oauth", "iam", "vpn"]) or "身份认证" in t or "统一登录" in t:
            return {"category": "AUTH_SSO", "icon": "🔑", "role": "SSO & Identity Provider", "color": "#f59e0b", "desc": "统一身份认证与单点登录"}
        elif any(k in h for k in ["api", "open", "rest", "v1", "v2", "service", "graphql", "gw", "gateway"]):
            return {"category": "API_GATEWAY", "icon": "⚡", "role": "API Gateway & Microservices", "color": "#3b82f6", "desc": "核心网关与API服务"}
        elif any(k in h for k in ["admin", "manage", "oa", "portal", "dashboard", "console", "erp", "crm"]):
            return {"category": "ADMIN_PORTAL", "icon": "🖥️", "role": "Admin & Internal Portal", "color": "#ef4444", "desc": "内部办公与管理控制台"}
        elif any(k in h for k in ["dev", "test", "stage", "staging", "uat", "qa", "sit", "beta", "sandbox"]):
            return {"category": "DEV_TEST", "icon": "🧪", "role": "Dev / QA / Staging Environment", "color": "#8b5cf6", "desc": "测试与预发布环境"}
        elif any(k in h for k in ["cdn", "static", "img", "images", "res", "assets", "oss", "cos", "files"]):
            return {"category": "STATIC_CDN", "icon": "📦", "role": "Static Assets & Storage", "color": "#10b981", "desc": "静态资源与对象存储"}
        
        return {"category": "GENERAL_WEB", "icon": "🌐", "role": "General Web Application", "color": "#64748b", "desc": "通用Web应用系统"}

    def _check_takeover_risk(self, cnames: List[str], body: str, status_code: int) -> Optional[Dict[str, Any]]:
        for service_name, fp in TAKEOVER_FINGERPRINTS.items():
            matched_cname = any(any(pat in c.lower() for pat in fp["cnames"]) for c in (cnames or []))
            if matched_cname and (fp["body"].lower() in (body or "").lower() or status_code in fp.get("status", [])):
                return {
                    "vulnerable": True,
                    "service": service_name,
                    "evidence": f"CNAME matches {service_name} signature and body contains dangling pattern."
                }
        return None

    async def _query_crt_sh(self) -> Set[str]:
        results = set()
        if not self.root_domain or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.root_domain):
            return results
        try:
            url = f"https://crt.sh/?q=%.{self.root_domain}&output=json"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8), trust_env=False) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            names = entry.get("name_value", "").split("\n")
                            for n in names:
                                n = n.strip().lower()
                                if n.startswith("*."):
                                    n = n[2:]
                                if n.endswith(self.root_domain):
                                    results.add(n)
        except Exception as e:
            logger.debug(f"crt.sh lookup skipped: {e}")
        return results

    async def _resolve_dns(self, hostname: str) -> Dict[str, Any]:
        ips = []
        cnames = []
        try:
            loop = asyncio.get_event_loop()
            addrinfo = await loop.getaddrinfo(hostname, None)
            for item in addrinfo:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            # gethostbyname_ex exposes aliases on platforms where the resolver
            # returns a CNAME chain; keep them as evidence for takeover checks.
            _, aliases, _ = await loop.run_in_executor(None, socket.gethostbyname_ex, hostname)
            cnames = sorted({str(alias).rstrip('.').lower() for alias in aliases if alias})
        except Exception:
            pass
        return {"ips": ips, "cnames": cnames}

    async def _probe_subdomain_web(self, hostname: str) -> Optional[Dict[str, Any]]:
        role_info = self._classify_sub_asset_role(hostname)
        is_target = hostname == self.target_host
        port_suffix = f":{self.target_port}" if is_target and self.target_port not in (80, 443) else ""
        preferred_scheme = self.target_scheme if is_target else "https"
        preferred_url = f"{preferred_scheme}://{hostname}{port_suffix}"
        ownership_confirmed = self.scope_manager.is_in_scope(preferred_url)
        dns_result = await self._resolve_dns(hostname)

        asset = {
            "hostname": hostname,
            "url": preferred_url,
            "status": None,
            "title": "",
            "server": "",
            "ips": dns_result["ips"],
            "cnames": dns_result["cnames"],
            "is_cdn": False,
            "cdn_vendor": None,
            "role": role_info["role"],
            "category": role_info["category"],
            "icon": role_info["icon"],
            "color": role_info["color"],
            "tier": "Application Tier",
            "desc": role_info["desc"],
            "scheme": preferred_scheme,
            "takeover_risk": None,
            "discovery_state": "RESOLVED" if dns_result["ips"] else "DISCOVERED",
            "ownership_confirmed": ownership_confirmed,
            "visited": False
        }

        if not ownership_confirmed or not dns_result["ips"]:
            return asset

        schemes = [preferred_scheme]
        if not is_target:
            schemes.append("http")
        timeout = aiohttp.ClientTimeout(total=5.0)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            for scheme in schemes:
                probe_url = f"{scheme}://{hostname}{port_suffix}"
                try:
                    async with session.get(probe_url, allow_redirects=False, ssl=False) as resp:
                        raw_body = await resp.content.read(65536)
                        body = raw_body.decode(resp.charset or "utf-8", errors="replace")
                        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                        asset.update({
                            "url": str(resp.url),
                            "status": resp.status,
                            "title": re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else "",
                            "server": resp.headers.get("Server", ""),
                            "scheme": scheme,
                            "discovery_state": "VISITED",
                            "visited": True
                        })
                        takeover = self._check_takeover_risk(dns_result["cnames"], body, resp.status)
                        asset["takeover_risk"] = takeover
                        if takeover:
                            self.risk_findings.append({
                                "id": f"sub-risk-takeover-{hostname}",
                                "category": "VULN",
                                "severity": "HIGH",
                                "level": "HIGH",
                                "title": f"疑似子域名接管 ({hostname})",
                                "url": str(resp.url),
                                "param": "",
                                "impact": f"{hostname} 的 DNS CNAME 与 {takeover['service']} 服务指纹匹配，可能存在悬挂资源被接管风险。",
                                "evidence": {
                                    "response_status": resp.status,
                                    "cnames": dns_result["cnames"],
                                    "service": takeover["service"],
                                    "matched_snippet": takeover["evidence"]
                                },
                                "remediation": "确认 DNS 记录与云服务资源归属；不再使用的记录应及时删除，使用中的资源应重新绑定并限制服务端响应。",
                                "verified": 1,
                                "cvss_score": 7.5,
                                "status": "OPEN"
                            })
                        self._evaluate_sub_asset_risks(asset, body)
                        return asset
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
        return asset

    def _evaluate_sub_asset_risks(self, sub_asset: Dict[str, Any], body: str) -> None:
        title = sub_asset.get("title", "")
        hostname = sub_asset.get("hostname", "")
        if "index of /" in (title or "").lower() or "directory listing" in (body or "").lower():
            self.risk_findings.append({
                "id": f"sub-risk-dirlist-{hostname}",
                "category": "VULN",
                "severity": "HIGH",
                "level": "HIGH",
                "title": f"子资产存在目录遍历/索引泄露 ({hostname})",
                "url": sub_asset.get("url", hostname),
                "param": "",
                "impact": f"子资产 {hostname} 开启了 Web 目录列表，可能泄露源码、备份和配置文件。",
                "evidence": {
                    "response_status": sub_asset.get("status"),
                    "matched_snippet": f"Title matched 'Index of /': {title}",
                    "ips": sub_asset.get("ips", [])
                },
                "remediation": "在 Web 服务器 (Nginx/Apache) 配置中禁用 autoindex 指令。",
                "verified": 1,
                "cvss_score": 7.5,
                "status": "OPEN"
            })

    async def expand_and_probe_all(self, pages_data: List[Dict[str, Any]] = None, js_scripts: List[Dict[str, Any]] = None, external_links: List[str] = None) -> Dict[str, Any]:
        self.discovered_subdomains.add(self.target_host or "localhost")
        extracted = self.passive_extract_from_crawled_content(pages_data, js_scripts, external_links)
        self.discovered_subdomains.update(extracted)

        # 公网证书透明度属于可选外部数据源；本地/离线模式默认不访问。
        if self.enable_external_sources:
            crt_domains = await self._query_crt_sh()
            self.discovered_subdomains.update(crt_domains)

        active_sub_assets = []
        for host in sorted(self.discovered_subdomains):
            if host:
                active_sub_assets.append(await self._probe_subdomain_web(host))

        return {
            "root_domain": self.root_domain,
            "active_sub_assets_count": sum(1 for item in active_sub_assets if item.get("visited")),
            "sub_assets": active_sub_assets,
            "risk_findings": self.risk_findings,
            "topology_cluster": {"nodes": active_sub_assets}
        }

    async def run(self, context: ScanContext) -> None:
        self.target_url = context.target_url
        self.auth_domains = context.auth_domains
        parsed = urlparse(self.target_url)
        self.target_host = parsed.netloc.split(":")[0].lower()
        self.target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.target_scheme = parsed.scheme or "http"
        self.root_domain = self._extract_root_domain(self.target_host)
        self.enable_external_sources = bool(context.scan_scope.get("enable_external_asset_sources", False))
        
        self.scope_manager = SRCScopingEngine(auth_domains=self.auth_domains)
        res = await self.expand_and_probe_all(
            pages_data=context.crawled_pages,
            js_scripts=context.js_scripts,
            external_links=context.external_links
        )
        context.sub_assets = res.get("sub_assets", [])
        context.topology_cluster = res.get("topology_cluster", {})
        context.add_findings(res.get("risk_findings", []))

        # --- 任务 1: 子资产递归爬取联动 ---
        from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler
        
        existing_urls = {p.get("url") for p in context.crawled_pages if p.get("url")}
        
        for asset in context.sub_assets:
            if asset.get("visited") and asset.get("ownership_confirmed"):
                asset_url = asset.get("url")
                # 避免重复爬取主目标 (主目标在 crawler 自身已深度爬取)
                if asset_url.rstrip("/") == self.target_url.rstrip("/"):
                    continue
                    
                logger.info(f"Starting secondary crawl for sub-asset: {asset_url}")
                crawler = AssetCrawler(
                    base_url=asset_url,
                    auth_domains=self.auth_domains,
                    max_depth=2,  # 深度限制 2
                    max_pages=15, # 页面数限制 15
                    qps_limit=5.0
                )
                
                try:
                    crawl_res = await crawler.crawl()
                    pages = crawl_res.get("pages", [])
                    
                    # 合并 crawled_pages 并去重
                    for p in pages:
                        url = p.get("url")
                        if url and url not in existing_urls:
                            context.crawled_pages.append(p)
                            existing_urls.add(url)
                except Exception as e:
                    logger.debug(f"Secondary crawl failed for {asset_url}: {e}")

