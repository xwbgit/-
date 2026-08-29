"""
子资产漏扫扩展 - 端口扫描、漏洞检测、关联分析 测试用例
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from plugins.scanner_extensions.sub_assets.port_scanner import (
    AsyncPortScanner, PortResult, HostScanResult,
    TOP_100_PORTS, HIGH_VALUE_PORTS, PORT_SERVICE_MAP
)
from plugins.scanner_extensions.sub_assets.vuln_scanner import (
    SubAssetVulnScanner, VULN_PROBES
)
from plugins.scanner_extensions.sub_assets.asset_correlator import (
    AssetCorrelator, AssetRiskProfile, IPCluster, CSegment,
    SEVERITY_WEIGHTS
)


# ─── Port Scanner Tests ─────────────────────────────────────────────────────

class TestPortScanner:

    def test_port_list_integrity(self):
        """确保端口列表无重复且在合理范围内"""
        assert len(TOP_100_PORTS) == len(set(TOP_100_PORTS)), "TOP_100_PORTS has duplicates"
        assert all(1 <= p <= 65535 for p in TOP_100_PORTS), "Port out of range"
        assert len(HIGH_VALUE_PORTS) <= len(TOP_100_PORTS)

    def test_port_service_map_coverage(self):
        """常用端口应有默认服务名"""
        critical_ports = [22, 80, 443, 3306, 6379, 8080, 27017]
        for port in critical_ports:
            assert port in PORT_SERVICE_MAP, f"Port {port} missing from PORT_SERVICE_MAP"

    def test_port_result_serialization(self):
        """PortResult 序列化完整性"""
        pr = PortResult(port=6379, state="open", service="Redis", banner="+PONG", risk_level="CRITICAL")
        d = pr.to_dict()
        assert d["port"] == 6379
        assert d["service"] == "Redis"
        assert d["risk_level"] == "CRITICAL"
        assert len(d["banner"]) <= 500

    def test_host_scan_result_serialization(self):
        """HostScanResult 序列化完整性"""
        ports = [
            PortResult(port=80, state="open", service="HTTP", risk_level="LOW"),
            PortResult(port=6379, state="open", service="Redis", risk_level="HIGH"),
        ]
        hsr = HostScanResult(hostname="test.example.com", ip="1.2.3.4", open_ports=ports, scan_time_ms=123.4, total_scanned=100)
        d = hsr.to_dict()
        assert d["hostname"] == "test.example.com"
        assert d["open_port_count"] == 2
        assert d["total_scanned"] == 100

    def test_risk_assessment_logic(self):
        """端口风险评估逻辑"""
        scanner = AsyncPortScanner()
        # Docker API port = HIGH or CRITICAL (port-based check)
        docker_risk = scanner._assess_port_risk(2375, "Docker API", "")
        assert docker_risk in ("HIGH", "CRITICAL")
        # Redis without auth = HIGH
        assert scanner._assess_port_risk(6379, "Redis", "+PONG") == "HIGH"
        # SSH = MEDIUM
        assert scanner._assess_port_risk(22, "SSH", "SSH-2.0-OpenSSH") == "MEDIUM"
        # Regular HTTP = LOW
        assert scanner._assess_port_risk(80, "HTTP", "HTTP/1.1 200") == "LOW"

    def test_fast_mode_uses_fewer_ports(self):
        """快扫模式使用更少端口"""
        fast_scanner = AsyncPortScanner(fast_mode=True)
        full_scanner = AsyncPortScanner(fast_mode=False)
        assert len(fast_scanner.port_list) < len(full_scanner.port_list)


# ─── Vulnerability Scanner Tests ─────────────────────────────────────────────

class TestVulnScanner:

    def test_probe_definitions_are_valid(self):
        """所有探针定义的字段完整"""
        for probe in VULN_PROBES:
            assert probe.name, "Probe name is empty"
            assert probe.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert probe.cvss_score > 0
            assert len(probe.target_services) > 0 or len(probe.target_ports) > 0
            assert probe.description
            assert probe.remediation

    def test_probe_covers_critical_services(self):
        """确保覆盖了最重要的服务"""
        probe_names = [p.name for p in VULN_PROBES]
        assert any("Redis" in n for n in probe_names)
        assert any("MongoDB" in n for n in probe_names)
        assert any("Docker" in n for n in probe_names)
        assert any("Actuator" in n for n in probe_names)

    def test_redis_probe_detects_noauth(self):
        """模拟 Redis 未授权 PONG 响应"""
        scanner = SubAssetVulnScanner()

        async def mock_open_connection(host, port):
            reader = AsyncMock()
            reader.read = AsyncMock(return_value=b"+PONG\r\n")
            writer = AsyncMock()
            writer.write = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer

        async def _run():
            with patch("asyncio.open_connection", side_effect=mock_open_connection):
                result = await scanner._probe_redis_noauth("127.0.0.1", 6379)
            return result

        result = asyncio.run(_run())
        assert result is not None
        assert result["vulnerable"] is True
        assert "+PONG" in result["evidence"]


# ─── Asset Correlator Tests ──────────────────────────────────────────────────

class TestAssetCorrelator:

    def test_ip_cluster_detection(self):
        """多个子域指向同一 IP 应被聚合"""
        correlator = AssetCorrelator()
        sub_assets = [
            {"hostname": "api.example.com", "ips": ["1.1.1.1"], "category": "API_GATEWAY"},
            {"hostname": "admin.example.com", "ips": ["1.1.1.1"], "category": "ADMIN_PORTAL"},
            {"hostname": "cdn.example.com", "ips": ["2.2.2.2"], "category": "STATIC_CDN"},
        ]
        port_results = []

        clusters = correlator._analyze_ip_clusters(sub_assets, port_results)

        cluster_1 = next((c for c in clusters if c.ip == "1.1.1.1"), None)
        assert cluster_1 is not None
        assert len(cluster_1.hostnames) == 2
        assert "api.example.com" in cluster_1.hostnames
        assert "admin.example.com" in cluster_1.hostnames

    def test_c_segment_analysis(self):
        """同 C 段资产应被关联"""
        correlator = AssetCorrelator()
        sub_assets = [
            {"hostname": "a.example.com", "ips": ["10.0.1.10"]},
            {"hostname": "b.example.com", "ips": ["10.0.1.20"]},
            {"hostname": "c.example.com", "ips": ["10.0.2.5"]},
        ]

        segments = correlator._analyze_c_segments(sub_assets)

        seg_1 = next((s for s in segments if "10.0.1" in s.network), None)
        assert seg_1 is not None
        assert seg_1.asset_count == 2

    def test_risk_scoring_weights(self):
        """风险评分应反映端口暴露和漏洞严重度"""
        correlator = AssetCorrelator()

        # 高危: 有 Redis 和 Docker 暴露
        profile_high = correlator._compute_risk_score(
            "risky.example.com",
            "ADMIN_PORTAL",
            [
                {"service": "Redis", "risk_level": "HIGH"},
                {"service": "Docker API", "risk_level": "CRITICAL"},
                {"service": "HTTP", "risk_level": "LOW"},
            ],
            [
                {"severity": "CRITICAL", "url": "tcp://risky.example.com:2375"},
            ]
        )

        # 低危: 只有 HTTP
        profile_low = correlator._compute_risk_score(
            "safe.example.com",
            "STATIC_CDN",
            [
                {"service": "HTTP", "risk_level": "LOW"},
            ],
            []
        )

        assert profile_high.risk_score > profile_low.risk_score
        assert profile_high.risk_level in ("HIGH", "CRITICAL")
        assert profile_low.risk_level == "LOW"

    def test_full_correlation_output_structure(self):
        """完整关联分析输出结构正确"""
        correlator = AssetCorrelator()
        sub_assets = [
            {"hostname": "web.example.com", "ips": ["1.1.1.1"], "category": "GENERAL_WEB"},
        ]
        port_results = [{
            "hostname": "web.example.com",
            "ip": "1.1.1.1",
            "open_ports": [{"port": 80, "service": "HTTP", "risk_level": "LOW"}]
        }]

        result = correlator.correlate(sub_assets, port_results, [], "test-task-001")

        assert "summary" in result
        assert "risk_profiles" in result
        assert "ip_clusters" in result
        assert "c_segments" in result
        assert result["summary"]["total_sub_assets"] == 1

    def test_severity_weight_completeness(self):
        """确保所有严重度都有权重"""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in SEVERITY_WEIGHTS
