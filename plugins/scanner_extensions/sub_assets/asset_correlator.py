"""
子资产关联分析与风险评分引擎 (Asset Correlator & Risk Scorer)
职责:
1. IP 聚合分析 (多个子域指向同一 IP = 同一服务器)
2. C 段关联分析 (识别同网段资产拓展攻击面)
3. 子资产风险综合评分 (暴露端口数、服务类型、漏洞严重度加权)
4. 输出拓扑增强数据供前端可视化渲染
"""

import logging
from collections import defaultdict
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field

from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.asset_correlator")


# ─── 风险权重配置 ──────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 10,
    "LOW": 3,
    "INFO": 1
}

SERVICE_RISK_WEIGHTS = {
    "Docker API": 50,
    "Redis": 35,
    "MongoDB": 35,
    "Elasticsearch": 30,
    "Memcached": 25,
    "MySQL/MariaDB": 20,
    "MySQL": 20,
    "PostgreSQL": 15,
    "MSSQL": 15,
    "SSH": 10,
    "RDP": 12,
    "FTP": 15,
    "VNC": 12,
    "Telnet": 20,
    "Zookeeper": 15,
    "RabbitMQ": 10,
}

CATEGORY_PRIORITY = {
    "AUTH_SSO": 5,
    "API_GATEWAY": 4,
    "ADMIN_PORTAL": 5,
    "DEV_TEST": 3,
    "STATIC_CDN": 1,
    "GENERAL_WEB": 2,
}


@dataclass
class AssetRiskProfile:
    """单个子资产的风险画像"""
    hostname: str
    ip: str = ""
    category: str = "GENERAL_WEB"
    open_port_count: int = 0
    high_risk_port_count: int = 0
    vuln_count: int = 0
    critical_vulns: int = 0
    risk_score: float = 0.0
    risk_level: str = "LOW"
    exposed_services: List[str] = field(default_factory=list)
    attack_surface_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "category": self.category,
            "open_port_count": self.open_port_count,
            "high_risk_port_count": self.high_risk_port_count,
            "vuln_count": self.vuln_count,
            "critical_vulns": self.critical_vulns,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "exposed_services": self.exposed_services,
            "attack_surface_summary": self.attack_surface_summary
        }


@dataclass
class IPCluster:
    """IP 聚合结果"""
    ip: str
    hostnames: List[str] = field(default_factory=list)
    total_open_ports: int = 0
    shared_services: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "hostname_count": len(self.hostnames),
            "total_open_ports": self.total_open_ports,
            "shared_services": self.shared_services,
            "risk_score": round(self.risk_score, 1)
        }


@dataclass
class CSegment:
    """C 段分析结果"""
    network: str  # e.g., "192.168.1.0/24"
    ips: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    asset_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "network": self.network,
            "ips": self.ips,
            "hostnames": self.hostnames,
            "asset_count": self.asset_count
        }


class AssetCorrelator(BaseScanner):
    """
    子资产关联分析与综合风险评分引擎
    
    将子域名发现、端口扫描、漏洞检测的结果进行交叉关联，
    生成 IP 聚合图谱、C 段分布图和子资产风险排名。
    """

    def __init__(self):
        super().__init__()
        self.risk_profiles: List[AssetRiskProfile] = []
        self.ip_clusters: List[IPCluster] = []
        self.c_segments: List[CSegment] = []

    def _compute_risk_score(
        self,
        hostname: str,
        category: str,
        open_ports: List[Dict[str, Any]],
        host_findings: List[Dict[str, Any]]
    ) -> AssetRiskProfile:
        """计算单个子资产的综合风险评分"""
        profile = AssetRiskProfile(hostname=hostname, category=category)
        profile.open_port_count = len(open_ports)

        score = 0.0

        # 1. 端口暴露评分
        high_risk_count = 0
        services_seen = set()
        for p in open_ports:
            service = p.get("service", "Unknown")
            risk = p.get("risk_level", "INFO")
            services_seen.add(service)

            if risk in ("HIGH", "CRITICAL"):
                high_risk_count += 1

            # 服务权重
            score += SERVICE_RISK_WEIGHTS.get(service, 2)

        profile.high_risk_port_count = high_risk_count
        profile.exposed_services = sorted(services_seen)

        # 2. 漏洞严重度评分
        for finding in host_findings:
            severity = finding.get("severity", "INFO")
            score += SEVERITY_WEIGHTS.get(severity, 1)
            profile.vuln_count += 1
            if severity == "CRITICAL":
                profile.critical_vulns += 1

        # 3. 资产类型加权
        cat_weight = CATEGORY_PRIORITY.get(category, 2)
        score *= (1 + cat_weight * 0.1)

        # 4. 归一化到 0-100
        profile.risk_score = min(score, 100.0)

        # 5. 定级
        if profile.risk_score >= 80:
            profile.risk_level = "CRITICAL"
        elif profile.risk_score >= 50:
            profile.risk_level = "HIGH"
        elif profile.risk_score >= 25:
            profile.risk_level = "MEDIUM"
        else:
            profile.risk_level = "LOW"

        # 6. 攻击面概要
        profile.attack_surface_summary = (
            f"{profile.open_port_count} 个开放端口，"
            f"{profile.high_risk_port_count} 个高危服务，"
            f"{profile.vuln_count} 个漏洞"
            f"{'（含 ' + str(profile.critical_vulns) + ' 个严重漏洞）' if profile.critical_vulns else ''}"
        )

        return profile

    def _analyze_ip_clusters(
        self,
        sub_assets: List[Dict[str, Any]],
        port_results: List[Dict[str, Any]]
    ) -> List[IPCluster]:
        """IP 聚合分析: 发现多个子域名指向同一 IP"""
        ip_to_hosts: Dict[str, List[str]] = defaultdict(list)

        for asset in sub_assets:
            hostname = asset.get("hostname", "")
            ips = asset.get("ips", [])
            for ip in ips:
                if ip and hostname:
                    ip_to_hosts[ip].append(hostname)

        clusters = []
        for ip, hostnames in ip_to_hosts.items():
            # 查找该 IP 对应的端口数据
            services = set()
            total_ports = 0
            for pr in port_results:
                if pr.get("ip") == ip or pr.get("hostname") in hostnames:
                    for op in pr.get("open_ports", []):
                        services.add(op.get("service", ""))
                        total_ports += 1

            cluster = IPCluster(
                ip=ip,
                hostnames=sorted(set(hostnames)),
                total_open_ports=total_ports,
                shared_services=sorted(services - {""}),
                risk_score=len(hostnames) * 10 + total_ports * 2
            )
            clusters.append(cluster)

        # 按风险评分降序
        clusters.sort(key=lambda c: c.risk_score, reverse=True)
        return clusters

    def _analyze_c_segments(
        self,
        sub_assets: List[Dict[str, Any]]
    ) -> List[CSegment]:
        """C 段关联分析: 识别同网段资产"""
        segment_map: Dict[str, CSegment] = {}

        for asset in sub_assets:
            hostname = asset.get("hostname", "")
            for ip in asset.get("ips", []):
                if not ip or ":" in ip:  # skip IPv6
                    continue
                parts = ip.split(".")
                if len(parts) != 4:
                    continue

                c_net = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                if c_net not in segment_map:
                    segment_map[c_net] = CSegment(network=c_net)

                seg = segment_map[c_net]
                if ip not in seg.ips:
                    seg.ips.append(ip)
                if hostname not in seg.hostnames:
                    seg.hostnames.append(hostname)
                seg.asset_count = len(seg.ips)

        # 只返回有多个 IP 的 C 段 (有关联意义的)
        meaningful = [s for s in segment_map.values() if s.asset_count >= 2]
        meaningful.sort(key=lambda s: s.asset_count, reverse=True)
        return meaningful

    def correlate(
        self,
        sub_assets: List[Dict[str, Any]],
        port_results: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        task_id: str
    ) -> Dict[str, Any]:
        """执行完整的关联分析"""

        # 按 hostname 索引端口数据和漏洞
        port_by_host: Dict[str, List[Dict]] = defaultdict(list)
        for pr in port_results:
            host = pr.get("hostname", "")
            port_by_host[host] = pr.get("open_ports", [])

        finding_by_host: Dict[str, List[Dict]] = defaultdict(list)
        for f in findings:
            url = f.get("url", "")
            for asset in sub_assets:
                hostname = asset.get("hostname", "")
                if hostname and hostname in url:
                    finding_by_host[hostname].append(f)
                    break

        # 1. 逐资产风险评分
        profiles = []
        for asset in sub_assets:
            hostname = asset.get("hostname", "")
            category = asset.get("category", "GENERAL_WEB")
            ip = (asset.get("ips") or [""])[0]
            open_ports = port_by_host.get(hostname, [])
            host_findings = finding_by_host.get(hostname, [])

            profile = self._compute_risk_score(hostname, category, open_ports, host_findings)
            profile.ip = ip
            profiles.append(profile)

        # 按风险评分降序
        profiles.sort(key=lambda p: p.risk_score, reverse=True)
        self.risk_profiles = profiles

        # 2. IP 聚合
        self.ip_clusters = self._analyze_ip_clusters(sub_assets, port_results)

        # 3. C 段分析
        self.c_segments = self._analyze_c_segments(sub_assets)

        # 4. 汇总统计
        total_assets = len(profiles)
        critical_assets = sum(1 for p in profiles if p.risk_level == "CRITICAL")
        high_risk_assets = sum(1 for p in profiles if p.risk_level == "HIGH")
        avg_score = sum(p.risk_score for p in profiles) / max(total_assets, 1)

        return {
            "task_id": task_id,
            "summary": {
                "total_sub_assets": total_assets,
                "critical_risk_assets": critical_assets,
                "high_risk_assets": high_risk_assets,
                "avg_risk_score": round(avg_score, 1),
                "ip_cluster_count": len(self.ip_clusters),
                "c_segment_count": len(self.c_segments),
            },
            "risk_profiles": [p.to_dict() for p in profiles],
            "ip_clusters": [c.to_dict() for c in self.ip_clusters],
            "c_segments": [s.to_dict() for s in self.c_segments],
            "top_risk_assets": [p.to_dict() for p in profiles[:10]]
        }

    async def run(self, context: ScanContext) -> None:
        """BaseScanner 标准接口"""
        sub_assets = context.sub_assets or []
        port_results = context.metadata.get("port_scan_results", [])
        findings = context.findings or []

        if not sub_assets:
            logger.info("[AssetCorrelator] No sub-assets to correlate.")
            return

        result = self.correlate(sub_assets, port_results, findings, context.task_id)

        # 注入到 ScanContext
        context.metadata["asset_correlation"] = result

        # 对高危集群生成告警
        for cluster in self.ip_clusters:
            if len(cluster.hostnames) >= 3:
                context.add_findings([{
                    "task_id": context.task_id,
                    "category": "VULN",
                    "severity": "MEDIUM",
                    "level": "MEDIUM",
                    "title": f"IP 聚合风险: {cluster.ip} 承载 {len(cluster.hostnames)} 个子域名",
                    "url": f"ip://{cluster.ip}",
                    "param": "",
                    "impact": (
                        f"IP 地址 {cluster.ip} 同时承载了 {len(cluster.hostnames)} 个子域名 "
                        f"({', '.join(cluster.hostnames[:5])})，单点故障或被攻破将影响全部服务。"
                    ),
                    "evidence": {
                        "matched_snippet": f"共享 IP: {cluster.ip}",
                        "hostnames": cluster.hostnames,
                        "shared_services": cluster.shared_services,
                        "open_ports": cluster.total_open_ports
                    },
                    "remediation": "建议分散部署关键服务至不同 IP/服务器，降低单点故障风险。",
                    "verified": 1,
                    "cvss_score": 5.0,
                    "status": "OPEN"
                }])

        logger.info(
            f"[AssetCorrelator] 关联分析完成: "
            f"{result['summary']['total_sub_assets']} 资产, "
            f"{result['summary']['critical_risk_assets']} 严重风险, "
            f"{result['summary']['ip_cluster_count']} 个 IP 聚合集群"
        )
