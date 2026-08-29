import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class ArchitectureFingerprintDetector:
    """基于已保存响应和扫描证据的技术栈指纹识别器。

    未出现可复核特征时保留“未识别”，不根据站点类型或域名猜测
    运行时、数据库及具体版本。
    """

    _SERVER_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
        (re.compile(r"apache(?:/([0-9][\w.\-]*))?", re.I), "Apache HTTP Server", "apache", "http_server"),
        (re.compile(r"nginx(?:/([0-9][\w.\-]*))?", re.I), "Nginx", "nginx", "nginx"),
        (re.compile(r"microsoft-iis(?:/([0-9][\w.\-]*))?", re.I), "Microsoft IIS", "microsoft", "internet_information_services"),
        (re.compile(r"caddy(?:/([0-9][\w.\-]*))?", re.I), "Caddy", "caddyserver", "caddy"),
    ]

    @staticmethod
    def _component(
        name: str,
        category: str,
        icon: str,
        *,
        version: str = "",
        confidence: int = 0,
        details: str = "未获得可复核的识别证据",
        evidence: Optional[List[str]] = None,
        detected: bool = False,
        cpe_candidate: Optional[str] = None,
    ) -> Dict[str, Any]:
        result = {
            "name": name,
            "version": version,
            "category": category,
            "icon": icon,
            "confidence": f"{confidence}%",
            "color": "#16a34a" if detected else "#64748b",
            "details": details,
            "detected": detected,
            "evidence": evidence or [],
        }
        if cpe_candidate:
            result["cpe_candidate"] = cpe_candidate
        return result

    @staticmethod
    def _cpe(vendor: str, product: str, version: str) -> Optional[str]:
        if not version:
            return None
        safe_version = re.sub(r"[^0-9A-Za-z._-]", "", version)
        if not safe_version:
            return None
        return f"cpe:2.3:a:{vendor}:{product}:{safe_version}:*:*:*:*:*:*:*"

    @classmethod
    def _detect_web_server(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        server = headers.get("server", "").strip()
        if headers.get("x-vercel-id") or server.lower() == "vercel":
            return cls._component(
                "Vercel Edge Network",
                "Cloud Gateway / CDN",
                "▲",
                confidence=98,
                details="响应头显式包含 Vercel 特征",
                evidence=[f"Server: {server}" if server else "X-Vercel-Id present"],
                detected=True,
            )

        for pattern, name, vendor, product in cls._SERVER_PATTERNS:
            match = pattern.search(server)
            if not match:
                continue
            version = match.group(1) or ""
            return cls._component(
                name,
                "Web Server / Reverse Proxy",
                "🌐",
                version=version,
                confidence=96 if version else 88,
                details="从 Server 响应头识别",
                evidence=[f"Server: {server}"],
                detected=True,
                cpe_candidate=cls._cpe(vendor, product, version),
            )

        if server:
            return cls._component(
                server,
                "Web Server / Gateway",
                "🌐",
                confidence=70,
                details="保留原始 Server 响应头，未做产品或版本猜测",
                evidence=[f"Server: {server}"],
                detected=True,
            )
        return cls._component("未识别 Web 服务器", "Web Server / Gateway", "🌐")

    @classmethod
    def _detect_frontend(cls, html: str) -> Dict[str, Any]:
        patterns = [
            (r"(?:__next_data__|id=[\"']__next[\"']|[/\"']_next/)", "Next.js / React", "next.js", "next.js", "Next.js 页面特征"),
            (r"(?:data-reactroot|react-dom(?:\.production)?(?:\.min)?\.js)", "React", "facebook", "react", "React DOM 特征"),
            (r"(?:__vue__|data-v-[0-9a-f]+|vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js)", "Vue.js", "vuejs", "vue", "Vue 页面特征"),
            (r"bootstrap(?:@|[-./])([0-9]+(?:\.[0-9]+){1,2})", "Bootstrap", "getbootstrap", "bootstrap", "Bootstrap 资源路径"),
        ]
        for raw_pattern, name, vendor, product, source in patterns:
            match = re.search(raw_pattern, html, re.I)
            if not match:
                continue
            version = match.group(1) if match.lastindex else ""
            snippet = match.group(0)[:160]
            return cls._component(
                name,
                "Frontend Framework",
                "💻",
                version=version,
                confidence=94 if version else 85,
                details=f"从 {source} 识别",
                evidence=[snippet],
                detected=True,
                cpe_candidate=cls._cpe(vendor, product, version),
            )
        return cls._component("未识别前端框架", "Frontend Framework", "💻")

    @classmethod
    def _detect_backend(cls, headers: Dict[str, str], html: str) -> Dict[str, Any]:
        powered_by = headers.get("x-powered-by", "").strip()
        cookies = headers.get("set-cookie", "")
        candidates = [
            (r"php(?:/([0-9][\w.\-]*))?", powered_by, "PHP", "php", "php"),
            (r"asp\.net(?:[/ ]([0-9][\w.\-]*))?", powered_by, "ASP.NET", "microsoft", "asp.net"),
            (r"express", powered_by, "Express", "openjs", "express"),
        ]
        for pattern, source, name, vendor, product in candidates:
            match = re.search(pattern, source, re.I)
            if not match:
                continue
            version = match.group(1) if match.lastindex else ""
            return cls._component(
                name,
                "Backend Runtime / Framework",
                "⚙️",
                version=version,
                confidence=96 if version else 85,
                details="从 X-Powered-By 响应头识别",
                evidence=[f"X-Powered-By: {powered_by}"],
                detected=True,
                cpe_candidate=cls._cpe(vendor, product, version),
            )

        if re.search(r"jsessionid", cookies, re.I):
            return cls._component(
                "Java Web 应用（具体框架未知）",
                "Backend Runtime / Framework",
                "⚙️",
                confidence=75,
                details="从 JSESSIONID Cookie 识别 Java Web 会话，不推断 Spring 或 Java 版本",
                evidence=["Set-Cookie contains JSESSIONID"],
                detected=True,
            )

        if re.search(r"(?:^|[/\"'])index\.php(?:[?\"']|$)", html, re.I):
            return cls._component(
                "PHP（版本未知）",
                "Backend Runtime / Framework",
                "⚙️",
                confidence=60,
                details="从页面内 .php 路径识别，不推断框架或版本",
                evidence=["HTML contains index.php path"],
                detected=True,
            )
        return cls._component("未识别后端运行时", "Backend Runtime / Framework", "⚙️")

    @classmethod
    def _detect_database(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        signatures = [
            (r"mysql(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){1,3})?", "MySQL", "oracle", "mysql"),
            (r"mariadb(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){1,3})?", "MariaDB", "mariadb", "mariadb"),
            (r"postgres(?:ql)?(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){0,2})?", "PostgreSQL", "postgresql", "postgresql"),
            (r"mongodb(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){0,2})?", "MongoDB", "mongodb", "mongodb"),
            (r"redis(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){0,2})?", "Redis", "redis", "redis"),
            (r"sqlite(?:[/\s_-]*)([0-9]+(?:\.[0-9]+){0,2})?", "SQLite", "sqlite", "sqlite"),
        ]
        for finding in findings:
            evidence = str(finding.get("evidence") or "")
            for pattern, name, vendor, product in signatures:
                match = re.search(pattern, evidence, re.I)
                if not match:
                    continue
                version = match.group(1) or ""
                finding_id = str(finding.get("id") or "unknown")
                return cls._component(
                    name,
                    "Database / Data Store",
                    "🗄️",
                    version=version,
                    confidence=90 if version else 70,
                    details="从已保存风险证据中识别，需结合人工复核",
                    evidence=[f"finding:{finding_id}"],
                    detected=True,
                    cpe_candidate=cls._cpe(vendor, product, version),
                )
        return cls._component("未识别数据库", "Database / Data Store", "🗄️")

    @classmethod
    def detect_architecture(
        cls,
        target_url: str,
        pages_data: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        parsed = urlparse(target_url)
        all_headers: Dict[str, str] = {}
        html_parts: List[str] = []
        for page in pages_data:
            headers = page.get("headers")
            if isinstance(headers, dict):
                all_headers.update({str(key).lower(): str(value) for key, value in headers.items()})
            content = page.get("html_content")
            if content:
                html_parts.append(str(content)[:10000])

        combined_html = "\n".join(html_parts)
        is_https = parsed.scheme.lower() == "https"
        hsts = all_headers.get("strict-transport-security")
        cors = all_headers.get("access-control-allow-origin")
        security_evidence = [f"URL scheme: {parsed.scheme or 'unknown'}"]
        if hsts:
            security_evidence.append("Strict-Transport-Security present")
        if cors:
            security_evidence.append(f"Access-Control-Allow-Origin: {cors}")
        security = cls._component(
            "HTTP 传输与边界配置",
            "Security Boundary",
            "🛡️",
            version="HTTPS" if is_https else "HTTP",
            confidence=100,
            details=(
                f"已观测协议：{'HTTPS' if is_https else 'HTTP'}；"
                f"HSTS：{'已配置' if hsts else '未观测到'}；"
                f"CORS 响应头：{cors if cors else '未观测到'}。未执行 TLS 版本握手时不推断 TLS 版本。"
            ),
            evidence=security_evidence,
            detected=True,
        )

        components = [
            cls._detect_frontend(combined_html),
            cls._detect_web_server(all_headers),
            cls._detect_backend(all_headers, combined_html),
            cls._detect_database(findings),
            security,
        ]
        layers = [
            {"id": "tier-1", "title": "① 前端呈现层", "role": "Frontend Framework", "component": components[0]},
            {"id": "tier-2", "title": "② Web 接入层", "role": "Gateway / Web Server", "component": components[1]},
            {"id": "tier-3", "title": "③ 应用运行层", "role": "Backend Runtime", "component": components[2]},
            {"id": "tier-4", "title": "④ 数据存储层", "role": "Database / Data Store", "component": components[3]},
            {"id": "tier-5", "title": "⑤ 传输与安全边界", "role": "Security Boundary", "component": components[4]},
        ]
        cpe_candidates = [
            component["cpe_candidate"]
            for component in components
            if component.get("cpe_candidate")
        ]
        return {
            "target_host": (parsed.hostname or "").lower(),
            "target_url": target_url,
            "analyzed_pages_count": len(pages_data),
            "layers": layers,
            "cpe_candidates": cpe_candidates,
            "fingerprint_policy": "EVIDENCE_ONLY",
        }
