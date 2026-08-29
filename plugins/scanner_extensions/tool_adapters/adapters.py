import hashlib
import json
import math
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from plugins.core.base import ScanContext

from .base import BaseToolAdapter, ToolExecutionError, ToolRunResult


SEVERITY_TO_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 0.0,
}


def _severity(value: Any, default: str = "INFO") -> str:
    normalized = str(value or default).split()[0].upper()
    aliases = {"INFORMATIONAL": "INFO", "WARNING": "LOW", "WARN": "LOW"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in SEVERITY_TO_CVSS else default


def _scan_url(raw_url: str) -> str:
    """工具调用不携带 URL 查询串和片段，避免把业务令牌写入进程参数或日志。"""
    parsed = urlsplit(raw_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _redact_text(value: Any, limit: int = 500) -> str:
    text = str(value or "")[:limit]
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)((?:password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*)([^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    return text


class NucleiAdapter(BaseToolAdapter):
    tool_name = "nuclei"
    executable_names = ("nuclei", "nuclei.exe")
    version_args = ("-version",)
    accepted_exit_codes = {0}

    @staticmethod
    def parse_findings(content: str, version: str = "") -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for item in BaseToolAdapter.parse_json_lines(content):
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            template_id = str(item.get("template-id") or item.get("templateID") or "unknown-template")
            title = str(info.get("name") or item.get("matcher-name") or template_id)
            severity = _severity(info.get("severity"))
            raw_matched_at = str(item.get("matched-at") or item.get("host") or "")
            matched_at = _scan_url(raw_matched_at) if raw_matched_at else ""
            matcher = str(item.get("matcher-name") or item.get("type") or "")
            references = info.get("reference") or []
            if isinstance(references, str):
                references = [references]
            findings.append({
                "id": str(uuid.uuid4()),
                "category": "VULN",
                "title": f"[Nuclei] {title}",
                "severity": severity,
                "url": matched_at,
                "param": f"Template: {template_id}",
                "evidence": {
                    "tool": "nuclei",
                    "tool_version": version,
                    "template_id": template_id,
                    "matcher": matcher,
                    "matched_at": matched_at,
                    "timestamp": item.get("timestamp"),
                    "matched_snippet": f"template={template_id}; matcher={matcher or 'default'}; target={matched_at}",
                    "references": [str(ref)[:500] for ref in references[:10]],
                },
                "impact": _redact_text(info.get("description") or "Nuclei 签名模板在授权目标上命中，需结合模板和响应证据复核影响。", 2000),
                "remediation": _redact_text(info.get("remediation") or "核对模板引用的安全公告，升级受影响组件或修正对应配置。", 2000),
                "verified": 1 if item.get("matcher-status") is True else 0,
                "cvss_score": SEVERITY_TO_CVSS[severity],
                "status": "OPEN",
                "src_type": "SRC_EXPLOITABLE" if item.get("matcher-status") is True else "SRC_SUSPECTED",
                "confidence_status": "CONFIRMED" if item.get("matcher-status") is True else "SUSPECTED",
            })
        return findings

    async def run(self, context: ScanContext, timeout_seconds: float) -> tuple[ToolRunResult, List[Dict[str, Any]]]:
        self.assert_authorized(context)
        executable = self.find_executable()
        if not executable:
            return ToolRunResult(tool=self.tool_name, status="SKIPPED", reason="nuclei executable not found"), []
        version = await self.get_version(executable)
        qps = max(1, min(20, int(float(context.scan_scope.get("qps_limit", 5)))))
        request_timeout = max(1, min(30, int(float(context.scan_scope.get("request_timeout", 10)))))
        with tempfile.TemporaryDirectory(prefix="das-nuclei-") as workdir:
            output_path = Path(workdir) / "findings.jsonl"
            command = [
                executable,
                "-u", _scan_url(context.target_url),
                "-jsonl",
                "-silent",
                "-no-color",
                "-output", str(output_path),
                "-rate-limit", str(qps),
                "-timeout", str(request_timeout),
                "-retries", "0",
                "-disable-unsigned-templates",
                "-disable-update-check",
                "-no-interactsh",
                "-exclude-tags", "dos,fuzz,intrusive,bruteforce",
                "-bulk-size", "1",
                "-concurrency", str(min(qps, 5)),
                "-response-size-read", "1048576",
                "-response-size-save", "1048576",
                "-max-host-error", "10",
            ]
            result = await self.runner.run(command, timeout_seconds=timeout_seconds)
            content = self.read_text(output_path) or result.stdout
        if result.timed_out:
            return ToolRunResult(
                tool=self.tool_name,
                status="TIMED_OUT",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=f"timeout after {timeout_seconds}s",
                command=result.command,
            ), []
        if result.exit_code not in self.accepted_exit_codes:
            return ToolRunResult(
                tool=self.tool_name,
                status="FAILED",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=(result.stderr or "nuclei returned a non-zero exit code")[:500],
                command=result.command,
            ), []
        findings = self.parse_findings(content, version)
        return ToolRunResult(
            tool=self.tool_name,
            status="COMPLETED",
            version=version,
            executable=executable,
            duration_seconds=result.duration_seconds,
            exit_code=result.exit_code,
            findings_count=len(findings),
            command=result.command,
        ), findings


class GitleaksAdapter(BaseToolAdapter):
    tool_name = "gitleaks"
    executable_names = ("gitleaks", "gitleaks.exe")
    version_args = ("version",)
    accepted_exit_codes = {0, 1}

    @staticmethod
    def parse_findings(content: str, url_map: Dict[str, str], version: str = "") -> List[Dict[str, Any]]:
        try:
            payload = json.loads(content or "[]")
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []
        findings: List[Dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            file_name = Path(str(item.get("File") or item.get("file") or "")).name
            target_url = url_map.get(file_name, "")
            rule_id = str(item.get("RuleID") or item.get("ruleID") or "secret")
            description = str(item.get("Description") or item.get("description") or rule_id)
            line = item.get("StartLine") or item.get("startLine")
            fingerprint = str(item.get("Fingerprint") or item.get("fingerprint") or "")
            findings.append({
                "id": str(uuid.uuid4()),
                "category": "SENSITIVE",
                "title": f"[Gitleaks] {description}",
                "severity": "HIGH",
                "url": target_url,
                "param": f"Rule: {rule_id}",
                "evidence": {
                    "tool": "gitleaks",
                    "tool_version": version,
                    "rule_id": rule_id,
                    "source_line": line,
                    "fingerprint": fingerprint,
                    "secret_redacted": True,
                    "matched_snippet": f"rule={rule_id}; line={line or 'unknown'}; secret=[REDACTED]",
                },
                "impact": "公开页面或资源中出现疑似密钥材料，可能导致账号、云资源或第三方服务被非授权访问。",
                "remediation": "立即下线公开内容、吊销并轮换密钥，排查使用记录，后续通过密钥管理服务注入。",
                "verified": 0,
                "cvss_score": 8.0,
                "status": "OPEN",
                "src_type": "SRC_SUSPECTED",
                "confidence_status": "SUSPECTED",
            })
        return findings

    @staticmethod
    def _write_scan_inputs(directory: Path, context: ScanContext) -> Dict[str, str]:
        url_map: Dict[str, str] = {}
        sources: List[tuple[str, str, str]] = []
        remaining_bytes = 20 * 1024 * 1024
        for page in context.crawled_pages:
            url = str(page.get("url") or "")
            content = page.get("html_content")
            if url and content:
                sources.append((url, str(content), ".html"))
        for script in context.js_scripts:
            if not isinstance(script, dict):
                continue
            url = str(script.get("url") or "")
            content = script.get("content") or script.get("js_content")
            if url and content:
                sources.append((url, str(content), ".js"))

        for url, content, suffix in sources:
            if remaining_bytes <= 0:
                break
            encoded = content.encode("utf-8")[: min(2 * 1024 * 1024, remaining_bytes)]
            name = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24] + suffix
            (directory / name).write_bytes(encoded)
            url_map[name] = url
            remaining_bytes -= len(encoded)
        return url_map

    async def run(self, context: ScanContext, timeout_seconds: float) -> tuple[ToolRunResult, List[Dict[str, Any]]]:
        self.assert_authorized(context)
        executable = self.find_executable()
        if not executable:
            return ToolRunResult(tool=self.tool_name, status="SKIPPED", reason="gitleaks executable not found"), []
        version = await self.get_version(executable)
        with tempfile.TemporaryDirectory(prefix="das-gitleaks-") as workdir:
            work_path = Path(workdir)
            source_path = work_path / "sources"
            source_path.mkdir()
            url_map = self._write_scan_inputs(source_path, context)
            if not url_map:
                return ToolRunResult(
                    tool=self.tool_name,
                    status="SKIPPED",
                    version=version,
                    executable=executable,
                    reason="no crawled page or script content available",
                ), []
            report_path = work_path / "gitleaks.json"
            command = [
                executable,
                "dir", str(source_path),
                "--report-format", "json",
                "--report-path", str(report_path),
                "--redact=100",
                "--no-banner",
                "--no-color",
                "--max-archive-depth", "0",
                "--max-decode-depth", "0",
                "--max-target-megabytes", "10",
            ]
            result = await self.runner.run(command, timeout_seconds=timeout_seconds)
            content = self.read_text(report_path)
        if result.timed_out:
            return ToolRunResult(
                tool=self.tool_name,
                status="TIMED_OUT",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=f"timeout after {timeout_seconds}s",
                command=result.command,
            ), []
        if result.exit_code not in self.accepted_exit_codes:
            return ToolRunResult(
                tool=self.tool_name,
                status="FAILED",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=(result.stderr or "gitleaks returned an unexpected exit code")[:500],
                command=result.command,
            ), []
        findings = self.parse_findings(content, url_map, version)
        return ToolRunResult(
            tool=self.tool_name,
            status="COMPLETED",
            version=version,
            executable=executable,
            duration_seconds=result.duration_seconds,
            exit_code=result.exit_code,
            findings_count=len(findings),
            command=result.command,
        ), findings


class ZapBaselineAdapter(BaseToolAdapter):
    tool_name = "owasp-zap-baseline"
    executable_names = ("zap-baseline.py", "zap-baseline")
    version_args = ("-h",)
    accepted_exit_codes = {0, 1, 2}

    @staticmethod
    def parse_findings(content: str, version: str = "") -> List[Dict[str, Any]]:
        try:
            report = json.loads(content or "{}")
        except json.JSONDecodeError:
            return []
        findings: List[Dict[str, Any]] = []
        for site in report.get("site", []) if isinstance(report, dict) else []:
            if not isinstance(site, dict):
                continue
            for alert in site.get("alerts", []):
                if not isinstance(alert, dict):
                    continue
                instances = alert.get("instances") or [{}]
                first = instances[0] if isinstance(instances, list) and instances else {}
                risk_code = str(alert.get("riskcode") or "0")
                severity = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}.get(risk_code, "INFO")
                url = str(first.get("uri") or site.get("@name") or "")
                plugin_id = str(alert.get("pluginid") or "unknown")
                evidence = _redact_text(first.get("evidence"), 300)
                findings.append({
                    "id": str(uuid.uuid4()),
                    "category": "VULN",
                    "title": f"[OWASP ZAP] {alert.get('alert') or alert.get('name') or plugin_id}",
                    "severity": severity,
                    "url": url,
                    "param": str(first.get("param") or f"Plugin: {plugin_id}"),
                    "evidence": {
                        "tool": "owasp-zap-baseline",
                        "tool_version": version,
                        "plugin_id": plugin_id,
                        "method": first.get("method"),
                        "evidence_redacted": True,
                        "matched_snippet": f"passive-rule={plugin_id}; evidence={evidence}"[:500],
                        "reference": str(alert.get("reference") or "")[:1000],
                    },
                    "impact": _redact_text(alert.get("desc") or "ZAP 被动扫描规则在授权站点响应中发现安全风险。", 2000),
                    "remediation": _redact_text(alert.get("solution") or "根据 ZAP 规则编号和官方建议修正配置，修复后重新运行被动扫描。", 2000),
                    "verified": 0,
                    "cvss_score": SEVERITY_TO_CVSS[severity],
                    "status": "OPEN",
                    "src_type": "SRC_SUSPECTED",
                    "confidence_status": "SUSPECTED",
                })
        return findings

    async def run(self, context: ScanContext, timeout_seconds: float) -> tuple[ToolRunResult, List[Dict[str, Any]]]:
        self.assert_authorized(context)
        executable = self.find_executable()
        if not executable:
            return ToolRunResult(tool=self.tool_name, status="SKIPPED", reason="zap-baseline executable not found"), []
        version = await self.get_version(executable)
        max_minutes = max(1, int(math.ceil(timeout_seconds / 60)))
        with tempfile.TemporaryDirectory(prefix="das-zap-") as workdir:
            report_path = Path(workdir) / "zap-report.json"
            command = [
                executable,
                "-t", _scan_url(context.target_url),
                "-J", str(report_path),
                "-m", "1",
                "-T", str(max_minutes),
                "-I",
                "-s",
            ]
            result = await self.runner.run(command, timeout_seconds=timeout_seconds)
            content = self.read_text(report_path)
        if result.timed_out:
            return ToolRunResult(
                tool=self.tool_name,
                status="TIMED_OUT",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=f"timeout after {timeout_seconds}s",
                command=result.command,
            ), []
        if result.exit_code not in self.accepted_exit_codes:
            return ToolRunResult(
                tool=self.tool_name,
                status="FAILED",
                version=version,
                executable=executable,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                reason=(result.stderr or "ZAP baseline returned an unexpected exit code")[:500],
                command=result.command,
            ), []
        findings = self.parse_findings(content, version)
        return ToolRunResult(
            tool=self.tool_name,
            status="COMPLETED",
            version=version,
            executable=executable,
            duration_seconds=result.duration_seconds,
            exit_code=result.exit_code,
            findings_count=len(findings),
            command=result.command,
        ), findings
