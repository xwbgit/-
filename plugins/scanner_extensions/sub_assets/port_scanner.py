"""
异步端口扫描与服务探测引擎 (Async Port Scanner & Service Probe)
职责:
1. 对子资产进行异步 TCP Connect 扫描 (Top 100 常见端口)
2. Banner 抓取与服务识别 (HTTP/SSH/FTP/MySQL/Redis/RDP/Telnet 等)
3. 严格遵循 SRC 授权边界与并发限速
4. 输出标准化 PortScanResult 数据结构
"""

import asyncio
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse

from plugins.core.base import BaseScanner, ScanContext
from plugins.core.scope_manager import SRCScopingEngine

logger = logging.getLogger("das_sentinel.port_scanner")


# ─── 端口数据库 ──────────────────────────────────────────────────────────────

TOP_100_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
    135, 139, 143, 161, 389, 443, 445, 465, 512, 513,
    514, 515, 548, 554, 587, 631, 636, 873, 993, 995,
    1080, 1099, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086,
    2087, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690, 4000,
    4443, 4444, 4848, 5000, 5432, 5555, 5900, 5984, 6000, 6379,
    6443, 6666, 7001, 7002, 7070, 7071, 7443, 8000, 8008, 8009,
    8080, 8081, 8083, 8088, 8090, 8161, 8443, 8444, 8500, 8800,
    8880, 8888, 8899, 9000, 9001, 9043, 9060, 9090, 9091, 9200,
    9300, 9418, 9443, 9999, 10000, 10443, 11211, 15672, 27017, 50000
]

# 快扫高价值端口子集 (扫描速度优先时使用)
HIGH_VALUE_PORTS: List[int] = [
    21, 22, 23, 25, 80, 443, 445, 1433, 1521, 2181,
    2375, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 7001,
    8000, 8080, 8443, 8888, 9090, 9200, 11211, 15672, 27017
]

# 服务指纹库 (Banner -> Service Name)
SERVICE_SIGNATURES: Dict[str, List[Tuple[str, str]]] = {
    # pattern, service_name
    "SSH": [(r"SSH-\d\.\d", "SSH")],
    "FTP": [(r"220[\s-]", "FTP"), (r"^530\s", "FTP")],
    "SMTP": [(r"^220.*SMTP", "SMTP"), (r"^220.*mail", "SMTP")],
    "MySQL": [(r"mysql|MariaDB", "MySQL/MariaDB")],
    "PostgreSQL": [(r"PostgreSQL", "PostgreSQL")],
    "Redis": [(r"-ERR", "Redis"), (r"\+PONG", "Redis"), (r"-NOAUTH", "Redis")],
    "MongoDB": [(r"ismaster", "MongoDB"), (r"MongoDB", "MongoDB")],
    "Elasticsearch": [(r"\"cluster_name\"", "Elasticsearch")],
    "RDP": [(r"\x03\x00\x00", "RDP")],
    "Telnet": [(r"^\xff\xfd", "Telnet"), (r"^login:", "Telnet")],
    "HTTP": [(r"HTTP/1\.[01]", "HTTP"), (r"HTTP/2", "HTTP/2")],
    "Memcached": [(r"^STAT ", "Memcached")],
    "Docker API": [(r"\"ApiVersion\"", "Docker API")],
    "Zookeeper": [(r"Zookeeper version", "Zookeeper")],
    "RabbitMQ": [(r"AMQP", "RabbitMQ")],
}

# 常见端口的默认服务映射 (当 Banner 无法识别时回退)
PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2181: "Zookeeper", 2375: "Docker",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 7001: "WebLogic", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    9090: "HTTP-Mgmt", 9200: "Elasticsearch", 11211: "Memcached",
    15672: "RabbitMQ-Mgmt", 27017: "MongoDB", 50000: "SAP",
}


@dataclass
class PortResult:
    """单个端口扫描结果"""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""
    tls: bool = False
    risk_level: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner[:500],  # 截断避免超大 banner
            "version": self.version,
            "tls": self.tls,
            "risk_level": self.risk_level
        }


@dataclass
class HostScanResult:
    """单个主机扫描结果"""
    hostname: str
    ip: str = ""
    open_ports: List[PortResult] = field(default_factory=list)
    scan_time_ms: float = 0.0
    total_scanned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "open_port_count": len(self.open_ports),
            "scan_time_ms": round(self.scan_time_ms, 1),
            "total_scanned": self.total_scanned
        }


class AsyncPortScanner(BaseScanner):
    """
    异步端口扫描器 (Async TCP Connect Scanner)
    
    安全约束:
    - 遵循 SRCScopingEngine 授权边界
    - 默认并发上限 50 (可配置)
    - 单端口超时 3 秒
    - 仅在授权范围内扫描
    """

    def __init__(
        self,
        concurrency: int = 50,
        timeout_sec: float = 3.0,
        port_list: Optional[List[int]] = None,
        fast_mode: bool = False
    ):
        super().__init__()
        self.concurrency = min(concurrency, 100)  # 硬上限
        self.timeout = timeout_sec
        self.port_list = port_list or (HIGH_VALUE_PORTS if fast_mode else TOP_100_PORTS)
        self.fast_mode = fast_mode
        self.results: List[HostScanResult] = []

    async def scan_port(
        self,
        host: str,
        port: int,
        semaphore: asyncio.Semaphore
    ) -> Optional[PortResult]:
        """扫描单个端口并尝试抓取 Banner"""
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

                banner = ""
                service = PORT_SERVICE_MAP.get(port, "Unknown")
                version = ""
                is_tls = False

                # 尝试抓取 Banner
                try:
                    # 对 HTTP(S) 端口发送简单请求
                    if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8081, 8088, 9090, 7001):
                        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        await writer.drain()

                    # 对 Redis 发送 PING
                    elif port == 6379:
                        writer.write(b"PING\r\n")
                        await writer.drain()

                    # 对 Memcached 发送 stats
                    elif port == 11211:
                        writer.write(b"stats\r\n")
                        await writer.drain()

                    data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, UnicodeDecodeError):
                    pass

                # Banner 指纹匹配
                if banner:
                    for svc_name, patterns in SERVICE_SIGNATURES.items():
                        for pattern, matched_service in patterns:
                            if re.search(pattern, banner, re.IGNORECASE):
                                service = matched_service
                                # 尝试提取版本号
                                ver_match = re.search(r"(\d+\.\d+(?:\.\d+)*)", banner)
                                if ver_match:
                                    version = ver_match.group(1)
                                break

                # 风险评估
                risk_level = self._assess_port_risk(port, service, banner)

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner,
                    version=version,
                    tls=is_tls,
                    risk_level=risk_level
                )

            except (ConnectionRefusedError, ConnectionResetError):
                return None  # closed
            except asyncio.TimeoutError:
                return None  # filtered / no response
            except OSError:
                return None
            except Exception as e:
                logger.debug(f"Port scan error {host}:{port}: {e}")
                return None

    def _assess_port_risk(self, port: int, service: str, banner: str) -> str:
        """基于端口/服务/Banner 评估风险等级"""
        banner_lower = banner.lower()

        # 高危: 数据库/缓存未授权
        if service in ("Redis", "Memcached", "MongoDB", "Elasticsearch", "Docker API"):
            if "-NOAUTH" not in banner and "requirepass" not in banner_lower:
                return "HIGH"

        # 高危: 管理后台暴露
        if port in (2375, 2376):  # Docker
            return "CRITICAL"
        if port == 9200:  # Elasticsearch
            return "HIGH"
        if port in (7001, 7002):  # WebLogic
            return "HIGH"
        if port == 8161:  # ActiveMQ
            return "HIGH"

        # 中危: 远程管理服务
        if service in ("SSH", "RDP", "VNC", "Telnet"):
            return "MEDIUM"

        # 中危: FTP
        if service == "FTP":
            if "anonymous" in banner_lower:
                return "HIGH"
            return "MEDIUM"

        # 低危: 一般 Web 服务
        if service in ("HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"):
            return "LOW"

        return "INFO"

    async def scan_host(self, hostname: str, ip: str = "") -> HostScanResult:
        """对单个主机执行全端口扫描"""
        import time
        start = time.monotonic()

        semaphore = asyncio.Semaphore(self.concurrency)
        target = ip or hostname

        tasks = [
            self.scan_port(target, port, semaphore)
            for port in self.port_list
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for r in results:
            if isinstance(r, PortResult) and r is not None:
                open_ports.append(r)

        elapsed = (time.monotonic() - start) * 1000

        host_result = HostScanResult(
            hostname=hostname,
            ip=ip,
            open_ports=sorted(open_ports, key=lambda p: p.port),
            scan_time_ms=elapsed,
            total_scanned=len(self.port_list)
        )

        logger.info(
            f"[PortScanner] {hostname} ({ip}): "
            f"{len(open_ports)}/{len(self.port_list)} ports open "
            f"in {elapsed:.0f}ms"
        )

        return host_result

    async def scan_multiple_hosts(
        self,
        targets: List[Dict[str, str]],
        scope_manager: Optional[SRCScopingEngine] = None
    ) -> List[HostScanResult]:
        """批量扫描多个主机 (尊重授权边界)"""
        results = []
        for target in targets:
            hostname = target.get("hostname", "")
            ip = target.get("ip", "")

            # 授权边界检查
            if scope_manager:
                check_url = f"http://{hostname}"
                if not scope_manager.is_in_scope(check_url):
                    logger.info(f"[PortScanner] Skipping {hostname}: out of scope")
                    continue

            result = await self.scan_host(hostname, ip)
            results.append(result)

        self.results = results
        return results

    async def run(self, context: ScanContext) -> None:
        """BaseScanner 标准接口: 从 ScanContext 获取子资产并扫描"""
        sub_assets = context.sub_assets or []
        if not sub_assets:
            logger.info("[PortScanner] No sub-assets to scan, skipping.")
            return

        scope_mgr = SRCScopingEngine(auth_domains=context.auth_domains)

        targets = []
        for asset in sub_assets:
            hostname = asset.get("hostname", "")
            ips = asset.get("ips", [])
            if hostname and asset.get("ownership_confirmed", False):
                targets.append({
                    "hostname": hostname,
                    "ip": ips[0] if ips else ""
                })

        if not targets:
            logger.info("[PortScanner] No authorized targets for port scanning.")
            return

        results = await self.scan_multiple_hosts(targets, scope_mgr)

        # 将端口扫描结果注入 ScanContext
        port_scan_data = [r.to_dict() for r in results]
        context.metadata["port_scan_results"] = port_scan_data

        # 生成端口暴露风险 Findings
        for host_result in results:
            for port in host_result.open_ports:
                if port.risk_level in ("HIGH", "CRITICAL"):
                    context.add_findings([{
                        "task_id": context.task_id,
                        "category": "VULN",
                        "severity": port.risk_level,
                        "level": port.risk_level,
                        "title": f"高危端口暴露: {host_result.hostname}:{port.port} ({port.service})",
                        "url": f"tcp://{host_result.hostname}:{port.port}",
                        "param": "",
                        "impact": f"子资产 {host_result.hostname} 暴露了 {port.service} 服务 (端口 {port.port})，可能导致未授权访问或信息泄露。",
                        "evidence": {
                            "matched_snippet": port.banner[:300] if port.banner else f"TCP port {port.port} is open",
                            "port": port.port,
                            "service": port.service,
                            "version": port.version,
                            "ip": host_result.ip
                        },
                        "remediation": f"建议限制 {port.service} 服务的网络访问范围，仅允许可信 IP 访问；若非必要，关闭该端口。",
                        "verified": 1,
                        "cvss_score": 8.5 if port.risk_level == "CRITICAL" else 7.0,
                        "status": "OPEN"
                    }])
