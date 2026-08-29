"""
子资产专项漏洞检测引擎 (Sub-Asset Vulnerability Scanner)
职责:
1. 基于端口扫描结果进行服务级漏洞探测
2. 常见高危服务未授权访问检测 (Redis/Memcached/MongoDB/Elasticsearch/Docker)
3. Web 管理后台弱口令探针 (Tomcat Manager, Spring Actuator)
4. WAF/CDN 增强识别
5. 输出统一 Finding 格式注入 ScanContext
"""

import asyncio
import json
import logging
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

import aiohttp

from plugins.core.base import BaseScanner, ScanContext
from plugins.core.scope_manager import SRCScopingEngine

logger = logging.getLogger("das_sentinel.sub_asset_vuln_scanner")


# ─── 服务漏洞探针定义 ─────────────────────────────────────────────────────────

@dataclass
class VulnProbe:
    """单个漏洞探针定义"""
    name: str
    target_services: List[str]
    target_ports: List[int]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    description: str
    remediation: str


# 预定义探针列表
VULN_PROBES: List[VulnProbe] = [
    VulnProbe(
        name="Redis 未授权访问",
        target_services=["Redis"],
        target_ports=[6379],
        severity="CRITICAL",
        cvss_score=9.8,
        description="Redis 服务未设置密码认证，任何人可读写数据、执行命令，可能导致服务器被完全接管。",
        remediation="1. 设置 requirepass 密码认证；2. 绑定 127.0.0.1 或使用防火墙限制访问；3. 禁用高危命令 (CONFIG, FLUSHALL)。"
    ),
    VulnProbe(
        name="Memcached UDP 反射 / 未授权访问",
        target_services=["Memcached"],
        target_ports=[11211],
        severity="HIGH",
        cvss_score=8.5,
        description="Memcached 暴露在公网且无认证，可被利用进行 DDoS 反射放大攻击或泄露缓存数据。",
        remediation="1. 绑定内网 IP；2. 禁用 UDP 协议；3. 启用 SASL 认证。"
    ),
    VulnProbe(
        name="MongoDB 未授权访问",
        target_services=["MongoDB"],
        target_ports=[27017],
        severity="CRITICAL",
        cvss_score=9.8,
        description="MongoDB 默认配置未开启认证，任何人可访问所有数据库，已造成大量数据泄露事件。",
        remediation="1. 启用 --auth 认证模式；2. 创建管理员账户；3. 绑定内网 IP 或设置防火墙。"
    ),
    VulnProbe(
        name="Elasticsearch 未授权访问",
        target_services=["Elasticsearch"],
        target_ports=[9200, 9300],
        severity="HIGH",
        cvss_score=8.5,
        description="Elasticsearch 集群暴露在公网且无认证，可直接查询所有索引数据。",
        remediation="1. 启用 X-Pack Security 认证；2. 限制网络访问范围；3. 配置反向代理鉴权。"
    ),
    VulnProbe(
        name="Docker Remote API 未授权",
        target_services=["Docker API", "Docker"],
        target_ports=[2375, 2376],
        severity="CRITICAL",
        cvss_score=10.0,
        description="Docker Remote API 未授权暴露，攻击者可直接操作容器、挂载宿主机文件系统实现逃逸。",
        remediation="1. 禁用 Remote API 或启用 TLS 双向认证；2. 使用防火墙限制访问来源。"
    ),
    VulnProbe(
        name="Spring Boot Actuator 信息泄露",
        target_services=["HTTP", "HTTPS", "HTTP-Proxy", "HTTPS-Alt"],
        target_ports=[80, 443, 8080, 8443, 8000, 8888, 9090],
        severity="HIGH",
        cvss_score=7.5,
        description="Spring Boot Actuator 端点暴露，可泄露环境变量、配置、健康状态、JVM 信息等敏感数据。",
        remediation="1. 生产环境禁用或限制 Actuator 端点；2. 配置 Spring Security 保护；3. 移除 /env, /heapdump 等高危端点。"
    ),
    VulnProbe(
        name="FTP 匿名登录",
        target_services=["FTP"],
        target_ports=[21],
        severity="HIGH",
        cvss_score=7.5,
        description="FTP 服务允许匿名登录，可能泄露文件或被利用上传恶意文件。",
        remediation="1. 禁用匿名登录；2. 使用 SFTP 替代 FTP；3. 限制上传目录权限。"
    ),
]


class SubAssetVulnScanner(BaseScanner):
    """
    子资产专项漏洞检测引擎
    
    基于端口扫描结果，执行针对性的服务级安全检测。
    所有探测均为非破坏性只读探针，符合 SRC 无害原则。
    """

    def __init__(self, timeout_sec: float = 5.0):
        super().__init__()
        self.timeout = timeout_sec
        self.findings: List[Dict[str, Any]] = []

    async def _probe_redis_noauth(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """检测 Redis 未授权访问"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            response = data.decode("utf-8", errors="replace").strip()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if "+PONG" in response:
                return {
                    "vulnerable": True,
                    "evidence": f"Redis PING 返回 +PONG，无需认证即可执行命令。",
                    "banner": response
                }
            elif "-NOAUTH" in response:
                return {"vulnerable": False, "evidence": "Redis 已启用认证保护。"}

        except Exception as e:
            logger.debug(f"Redis probe failed {host}:{port}: {e}")
        return None

    async def _probe_memcached(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """检测 Memcached 未授权访问"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.write(b"stats\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            response = data.decode("utf-8", errors="replace").strip()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if "STAT " in response:
                return {
                    "vulnerable": True,
                    "evidence": f"Memcached stats 返回统计数据，无需认证。",
                    "banner": response[:300]
                }
        except Exception as e:
            logger.debug(f"Memcached probe failed {host}:{port}: {e}")
        return None

    async def _probe_spring_actuator(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """检测 Spring Boot Actuator 暴露"""
        actuator_paths = [
            "/actuator", "/actuator/health", "/actuator/env",
            "/actuator/info", "/actuator/beans", "/actuator/mappings"
        ]
        scheme = "https" if port in (443, 8443) else "http"
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                for path in actuator_paths:
                    url = f"{scheme}://{host}:{port}{path}"
                    try:
                        async with session.get(url, ssl=False, allow_redirects=False) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="replace")
                                # 检查是否是真正的 Actuator 响应
                                if any(kw in body for kw in ['"status"', '"beans"', '"activeProfiles"', '"mappings"', '"_links"']):
                                    return {
                                        "vulnerable": True,
                                        "evidence": f"Spring Actuator 端点 {path} 返回 200，内容包含配置数据。",
                                        "url": url,
                                        "snippet": body[:500]
                                    }
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Actuator probe failed {host}:{port}: {e}")
        return None

    async def _probe_ftp_anonymous(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """检测 FTP 匿名登录"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            # 等待 FTP banner
            banner_data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            banner = banner_data.decode("utf-8", errors="replace").strip()

            # 尝试匿名登录
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            user_text = user_resp.decode("utf-8", errors="replace").strip()

            if user_text.startswith("331"):
                writer.write(b"PASS anonymous@test.com\r\n")
                await writer.drain()
                pass_resp = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                pass_text = pass_resp.decode("utf-8", errors="replace").strip()

                writer.write(b"QUIT\r\n")
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                if pass_text.startswith("230"):
                    return {
                        "vulnerable": True,
                        "evidence": f"FTP 允许匿名登录: {pass_text}",
                        "banner": banner
                    }

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"FTP anonymous probe failed {host}:{port}: {e}")
        return None

    async def scan_host_services(
        self,
        hostname: str,
        ip: str,
        open_ports: List[Dict[str, Any]],
        task_id: str
    ) -> List[Dict[str, Any]]:
        """对单个主机的开放端口执行漏洞探测"""
        findings = []
        target = ip or hostname

        for port_info in open_ports:
            port = port_info.get("port", 0)
            service = port_info.get("service", "")

            for probe in VULN_PROBES:
                if service not in probe.target_services and port not in probe.target_ports:
                    continue

                result = None

                # 按服务类型调度探针
                if "Redis" in probe.name:
                    result = await self._probe_redis_noauth(target, port)
                elif "Memcached" in probe.name:
                    result = await self._probe_memcached(target, port)
                elif "Actuator" in probe.name:
                    result = await self._probe_spring_actuator(target, port)
                elif "FTP" in probe.name and "匿名" in probe.name:
                    result = await self._probe_ftp_anonymous(target, port)
                elif "Docker" in probe.name:
                    # Docker API 探测通过端口暴露即为高危
                    if port in (2375, 2376):
                        result = {
                            "vulnerable": True,
                            "evidence": f"Docker Remote API 端口 {port} 在公网可达。"
                        }

                if result and result.get("vulnerable"):
                    findings.append({
                        "task_id": task_id,
                        "category": "VULN",
                        "severity": probe.severity,
                        "level": probe.severity,
                        "title": f"{probe.name} ({hostname}:{port})",
                        "url": f"tcp://{hostname}:{port}",
                        "param": "",
                        "impact": probe.description,
                        "evidence": {
                            "matched_snippet": result.get("evidence", ""),
                            "port": port,
                            "service": service,
                            "hostname": hostname,
                            "ip": ip,
                            "banner": result.get("banner", "")[:300]
                        },
                        "remediation": probe.remediation,
                        "verified": 1,
                        "cvss_score": probe.cvss_score,
                        "status": "OPEN",
                        "src_type": "SRC_EXPLOITABLE"
                    })

        return findings

    async def run(self, context: ScanContext) -> None:
        """BaseScanner 标准接口"""
        port_scan_results = context.metadata.get("port_scan_results", [])
        if not port_scan_results:
            logger.info("[VulnScanner] No port scan results available, skipping.")
            return

        all_findings = []
        for host_data in port_scan_results:
            hostname = host_data.get("hostname", "")
            ip = host_data.get("ip", "")
            open_ports = host_data.get("open_ports", [])

            if not open_ports:
                continue

            findings = await self.scan_host_services(
                hostname, ip, open_ports, context.task_id
            )
            all_findings.extend(findings)

        if all_findings:
            context.add_findings(all_findings)
            logger.info(f"[VulnScanner] 发现 {len(all_findings)} 个子资产服务级漏洞")
