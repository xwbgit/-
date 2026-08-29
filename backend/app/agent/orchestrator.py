import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from backend.app.config import settings
from backend.app.database import get_db_connection
from backend.app.agent.verifier import FindingVerifier
from plugins.core.base import ScanContext
from plugins.core.registry import scanner_registry

from plugins.core.src_filter import get_src_stats, is_src_noise
from backend.app.agent.advisor import RemediationAdvisor

logger = logging.getLogger("das_sentinel.orchestrator")

class InspectionOrchestrator:
    """智能巡检编排执行引擎"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.task_data = self._load_task()
        self.execution_trace: List[Dict[str, Any]] = []
        
    def _load_task(self) -> Dict[str, Any]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (self.task_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise ValueError(f"Task {self.task_id} not found in database.")
        return dict(row)

    def _update_task_status(self, status: str, progress: int, stage: str, summary: Optional[Dict[str, Any]] = None):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        if status == "RUNNING" and not self.task_data.get("started_at"):
            summary_json = json.dumps(summary, ensure_ascii=False) if summary is not None else self.task_data.get("summary")
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ?, started_at = ?, summary = ? WHERE id = ?",
                           (status, progress, stage, now, summary_json, self.task_id))
            self.task_data["started_at"] = now
        elif status in ("COMPLETED", "FAILED", "INTERRUPTED"):
            summary_json = json.dumps(summary or {}, ensure_ascii=False)
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ?, finished_at = ?, summary = ? WHERE id = ?",
                           (status, progress, stage, now, summary_json, self.task_id))
        elif summary is not None:
            summary_json = json.dumps(summary, ensure_ascii=False)
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ?, summary = ? WHERE id = ?",
                           (status, progress, stage, summary_json, self.task_id))
        else:
            cursor.execute("UPDATE tasks SET status = ?, progress = ?, current_stage = ? WHERE id = ?",
                           (status, progress, stage, self.task_id))
        conn.commit()
        conn.close()
        self.task_data.update({"status": status, "progress": progress, "current_stage": stage})
        if summary is not None:
            self.task_data["summary"] = json.dumps(summary, ensure_ascii=False)

    def _trace_step(self, scanner: str, executed: bool, reason: str) -> None:
        entry = {
            "scanner": scanner,
            "status": "EXECUTED" if executed else "SKIPPED",
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        self.execution_trace.append(entry)
        self._log_audit("TOOL_EXECUTE" if executed else "TOOL_SKIP", self.task_data["target_url"], json.dumps(entry, ensure_ascii=False))

    def _log_audit(self, action: str, target: str, details: str, status: str = "SUCCESS"):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        cursor.execute("""
        INSERT INTO audit_logs (timestamp, action, operator, target, details, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (now, action, "DAS_SENTINEL_AGENT", target, details, status))
        conn.commit()
        conn.close()

    async def run(self) -> Dict[str, Any]:
        """执行端到端全量智能巡检闭环流程 (已解耦)"""
        target_url = self.task_data["target_url"]
        auth_domains = json.loads(self.task_data["auth_domains"])
        scan_scope = json.loads(self.task_data["scan_scope"])
        
        logger.info(f"Starting inspection task [{self.task_id}] for {target_url}")
        self._update_task_status("RUNNING", 5, "正在进行授权边界校验与环境预检...")
        self._log_audit("TASK_START", target_url, f"启动巡检任务: {self.task_data['name']}")

        try:
            from plugins.core.base import ScanContext
            from plugins.core.registry import scanner_registry
            
            scanner_registry.discover_scanners(['plugins.scanner_core', 'plugins.scanner_extensions'])
            
            context = ScanContext(
                task_id=self.task_id,
                target_url=target_url,
                auth_domains=auth_domains,
                scan_scope=scan_scope
            )
            
            scanners_dict = {cls.__name__: cls for cls in scanner_registry.get_all_scanners()}
            
            # 阶段 1：资产发现
            if 'AssetCrawler' in scanners_dict:
                self._update_task_status("RUNNING", 15, "执行资产发现...")
                crawler = scanners_dict['AssetCrawler'](
                    base_url=target_url,
                    auth_domains=auth_domains,
                    max_depth=scan_scope.get("max_depth", 3),
                    max_pages=scan_scope.get("max_pages", 50),
                    qps_limit=scan_scope.get("qps_limit", 5.0)
                )
                await crawler.run(context)
                self._trace_step("AssetCrawler", True, "页面发现是所有检测的基础阶段")
            else:
                self._trace_step("AssetCrawler", False, "插件未加载")
                
            # 阶段 1.2：特殊链接提取与外链清洗 (link_processor 方向)
            if 'SmartLinkExtractor' in scanners_dict:
                link_ext = scanners_dict['SmartLinkExtractor']()
                await link_ext.run(context)
                self._trace_step("SmartLinkExtractor", True, "提取页面资源与外链供后续检测使用")
            else:
                self._trace_step("SmartLinkExtractor", False, "插件未加载")
                
            # 阶段 1.5：子资产扩展 (sub_assets 方向)
            if 'SubAssetExpander' in scanners_dict:
                self._update_task_status("RUNNING", 25, "执行子资产扩展...")
                sub = scanners_dict['SubAssetExpander']()
                await sub.run(context)
                self._trace_step("SubAssetExpander", True, "执行授权范围内的被动发现与可达性确认")
                
                # 任务5: WHOIS/ASN 增强
                if 'WhoisEnricher' in scanners_dict:
                    self._update_task_status("RUNNING", 30, "提取 WHOIS 与 ASN 资产归属情报...")
                    enricher = scanners_dict['WhoisEnricher']()
                    await enricher.run(context)
                    self._trace_step("WhoisEnricher", True, "完成资产 IP 的 WHOIS 归属查询")
                else:
                    self._trace_step("WhoisEnricher", False, "插件未加载")

                # 任务2: HTTPS 证书安全审计
                if 'CertAuditor' in scanners_dict:
                    cert_auditor = scanners_dict['CertAuditor']()
                    await cert_auditor.run(context)
                    self._trace_step("CertAuditor", True, "完成 HTTPS 证书与弱加密套件审计")
                else:
                    self._trace_step("CertAuditor", False, "插件未加载")
            else:
                self._trace_step("SubAssetExpander", False, "插件未加载")
                
            # 阶段 2：漏洞探测 (scanner_core)
            vuln_enabled = bool(scan_scope.get("enable_vuln_check", True))
            if vuln_enabled and 'VulnerabilityDetector' in scanners_dict:
                self._update_task_status("RUNNING", 35, "执行漏洞探测...")
                vuln = scanners_dict['VulnerabilityDetector'](target_url, auth_domains)
                await vuln.run(context)
                self._trace_step("VulnerabilityDetector", True, "任务已启用漏洞与弱配置检测")
            else:
                self._trace_step("VulnerabilityDetector", False, "任务关闭漏洞检测" if not vuln_enabled else "插件未加载")

            # 阶段 2.2：REST API 接口轻量探针 (api_fuzzer 方向)
            if vuln_enabled and 'RestApiProber' in scanners_dict:
                api_prober = scanners_dict['RestApiProber']()
                await api_prober.run(context)
                self._trace_step("RestApiProber", True, "漏洞检测开启且发现阶段可提供 API 端点")
            else:
                self._trace_step("RestApiProber", False, "任务关闭漏洞检测" if not vuln_enabled else "插件未加载")
                
            # 阶段 2.5：深度渗透
            if vuln_enabled and 'DeepExploitEngine' in scanners_dict:
                self._update_task_status("RUNNING", 50, "执行深度渗透...")
                deep = scanners_dict['DeepExploitEngine']()
                await deep.run(context)
                self._trace_step("DeepExploitEngine", True, "仅对已有发现执行非破坏性证据复核")
            else:
                self._trace_step("DeepExploitEngine", False, "任务关闭漏洞检测" if not vuln_enabled else "插件未加载")
                
            # 阶段 3 & 4：篡改和敏感数据
            tamper_enabled = bool(scan_scope.get("enable_tamper_check", True))
            if tamper_enabled and 'TamperDetector' in scanners_dict:
                self._update_task_status("RUNNING", 65, "执行篡改检测...")
                tamper = scanners_dict['TamperDetector'](auth_domains)
                await tamper.run(context)
                self._trace_step("TamperDetector", True, "任务已启用篡改、暗链与挂马检测")
            else:
                self._trace_step("TamperDetector", False, "任务关闭篡改检测" if not tamper_enabled else "插件未加载")
                
            sensitive_enabled = bool(scan_scope.get("enable_sensitive_check", True))
            if sensitive_enabled and 'SensitiveInspector' in scanners_dict:
                self._update_task_status("RUNNING", 80, "执行敏感信息检测...")
                sens = scanners_dict['SensitiveInspector'](custom_keywords=scan_scope.get('custom_sensitive_keywords', []))
                await sens.run(context)
                self._trace_step("SensitiveInspector", True, "任务已启用敏感信息检测")
            else:
                self._trace_step("SensitiveInspector", False, "任务关闭敏感信息检测" if not sensitive_enabled else "插件未加载")

            # 阶段 4.5：可选的真实开源工具编排（显式开启才会执行）
            if settings.ENABLE_EXTERNAL_TOOLS and 'OpenSourceToolScanner' in scanners_dict:
                self._update_task_status("RUNNING", 85, "执行已授权的开源安全工具编排...")
                external_scanner = scanners_dict['OpenSourceToolScanner']()
                await external_scanner.run(context)
                tool_runs = context.metadata.get("tool_runs", [])
                completed = sum(1 for item in tool_runs if item.get("status") == "COMPLETED")
                self._trace_step(
                    "OpenSourceToolScanner",
                    True,
                    f"适配器运行完成；实际执行 {completed} 个工具，详情见 tool_runs"
                )
            else:
                reason = "部署配置未开启外部工具" if not settings.ENABLE_EXTERNAL_TOOLS else "插件未加载"
                self._trace_step("OpenSourceToolScanner", False, reason)

            # 智能体去重与指纹归纳
            self._update_task_status("RUNNING", 90, "正在执行智能体去重、技术栈拓扑指纹识别与风险定级归纳...")
            from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
            preliminary_architecture = ArchitectureFingerprintDetector.detect_architecture(
                target_url,
                context.crawled_pages,
                context.findings
            )
            from plugins.scanner_extensions.vulnerability_intel.cve_matcher import CVEIntelMatcher
            cve_findings, cve_intel_summary = CVEIntelMatcher(settings.CVE_CATALOG_PATH).match(
                preliminary_architecture.get("cpe_candidates", [])
            )
            for finding in cve_findings:
                finding["url"] = target_url
            context.add_findings(cve_findings)

            all_raw_findings = context.findings
            all_raw_findings_pre_src = all_raw_findings.copy()
            src_eligible_findings = []
            for finding in all_raw_findings:
                finding["src_eligible"] = not is_src_noise(finding)
                if finding["src_eligible"]:
                    src_eligible_findings.append(finding)
            deduped_findings = FindingVerifier.deduplicate_findings(all_raw_findings)
            
            enriched_findings = [RemediationAdvisor.enhance_finding_advisory(f) for f in deduped_findings]
            
            architecture_info = ArchitectureFingerprintDetector.detect_architecture(
                target_url,
                context.crawled_pages,
                enriched_findings
            )
            architecture_info["vulnerability_intelligence"] = cve_intel_summary
            
            risk_summary = FindingVerifier.calculate_risk_summary(enriched_findings)
            risk_summary["total_pages_scanned"] = len(context.crawled_pages)
            risk_summary["total_assets_discovered"] = len(context.static_assets)
            risk_summary["total_external_links"] = len(context.external_links)
            risk_summary["total_sub_assets"] = len(context.sub_assets)
            if context.crawled_pages:
                risk_summary["scan_quality"] = "OBSERVED_RESPONSES"
                risk_summary["scan_quality_note"] = "至少取得一个可分析的目标页面或文本响应。"
            else:
                # 连接失败、空响应或不支持的内容类型不能被展示成“100 分/无风险”。
                # 保留任务记录便于定位与重试，但明确标记本次结果不具备安全结论。
                risk_summary["security_score"] = None
                risk_summary["status_level"] = "INCOMPLETE (未取得可分析的目标响应)"
                risk_summary["scan_quality"] = "INCOMPLETE_NO_PAGE_RESPONSES"
                risk_summary["scan_quality_note"] = "本次巡检未取得可分析的 HTML/JSON/文本响应，不能据此判断目标安全。"
            risk_summary["sub_assets"] = context.sub_assets
            risk_summary["topology_cluster"] = context.topology_cluster
            risk_summary["architecture"] = architecture_info
            risk_summary["execution_trace"] = self.execution_trace
            risk_summary["tool_runs"] = context.metadata.get("tool_runs", [])
            risk_summary["whois_data"] = context.metadata.get("whois_data", {})
            risk_summary["src_filter_stats"] = get_src_stats(all_raw_findings_pre_src, src_eligible_findings)

            crawl_results = {
                "pages": context.crawled_pages,
                "static_assets": context.static_assets,
                "api_endpoints": context.api_endpoints,
                "external_links": context.external_links,
                "sub_assets": context.sub_assets
            }
            self._save_findings_and_baseline(enriched_findings, crawl_results, risk_summary)

            self._update_task_status("RUNNING", 93, "扫描结果已固化，正在进行基线对比...", summary=risk_summary)
            from backend.app.baseline.baseline_service import BaselineService
            snapshots = BaselineService.get_latest_snapshots(target_url, limit=2)
            if len(snapshots) > 1:
                risk_summary["baseline_diff"] = BaselineService.compare_baselines(snapshots[1]["task_id"], self.task_id)
            else:
                risk_summary["baseline_diff"] = {"status": "INITIAL_BASELINE", "message": "首次巡检，已建立初始基线"}
                
            sub_asset_snapshots = BaselineService.get_latest_sub_asset_snapshots(target_url, limit=2)
            if len(sub_asset_snapshots) > 1:
                risk_summary["sub_asset_diff"] = BaselineService.compare_sub_assets(sub_asset_snapshots[1]["task_id"], self.task_id)
            else:
                risk_summary["sub_asset_diff"] = {"status": "INITIAL_BASELINE", "message": "首次子资产扫描，已建立初始基线"}

            self._update_task_status("RUNNING", 96, "基线对比完成，正在发送风险告警...", summary=risk_summary)
            from backend.app.baseline.alert_service import AlertService
            alert_ok = await AlertService.send_alert(self.task_data["name"], target_url, enriched_findings, risk_summary)
            risk_summary["alert_status"] = "SENT_OR_LOGGED" if alert_ok else "DELIVERY_FAILED"
            self._log_audit("ALERT_SENT", target_url, f"告警阶段结果: {risk_summary['alert_status']}", status="SUCCESS" if alert_ok else "FAILED")

            self._update_task_status("RUNNING", 98, "告警阶段完成，正在固化巡检报告...", summary=risk_summary)
            from backend.app.baseline.report_service import ReportService
            report_path = ReportService.generate_html_report(self.task_id)
            risk_summary["report_path"] = report_path
            self._log_audit("REPORT_GENERATED", target_url, f"报告已固化: {report_path}")

            final_stage = (
                "智能巡检完成，但未取得可分析目标响应；报告不构成安全结论"
                if not context.crawled_pages
                else "智能巡检闭环完成，报告已固化"
            )
            if not alert_ok:
                final_stage += "（外部告警投递失败，请检查配置）"
            self._update_task_status("COMPLETED", 100, final_stage, summary=risk_summary)
            layer_names = [layer.get("component", {}).get("name", "Unknown") for layer in architecture_info.get("layers", [])[:2]]
            self._log_audit("TASK_COMPLETE", target_url, f"巡检完成，发现总风险数: {len(enriched_findings)}，架构识别: {' + '.join(layer_names) or 'Unknown'}")
            
            return {
                "task_id": self.task_id,
                "target_url": target_url,
                "summary": risk_summary,
                "findings": enriched_findings,
                "architecture": architecture_info
            }

        except Exception as e:
            logger.exception(f"Inspection task failed: {e}")
            failure_summary = {"error": str(e), "execution_trace": self.execution_trace}
            self._update_task_status("FAILED", self.task_data.get("progress", 0), f"巡检中断异常: {str(e)}", summary=failure_summary)
            self._log_audit("TASK_ERROR", target_url, f"巡检异常: {str(e)}", status="FAILED")
            raise

    def _save_findings_and_baseline(self, findings: List[Dict[str, Any]], crawl_results: Dict[str, Any], summary: Dict[str, Any]):
        conn = get_db_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()
        
        pages = crawl_results.get("pages", [])
        static_assets = crawl_results.get("static_assets", set())
        api_endpoints = crawl_results.get("api_endpoints", set())
        external_links = crawl_results.get("external_links", set())
        
        # 1. 写入 findings
        for f in findings:
            raw_evidence = f.get("evidence") or {}
            ev_dict = dict(raw_evidence) if isinstance(raw_evidence, dict) else {
                "matched_snippet": str(raw_evidence)
            }
            if f.get("deep_audit"):
                ev_dict["deep_audit"] = f["deep_audit"]
            if f.get("exploit_chain"):
                ev_dict["exploit_chain"] = f["exploit_chain"]
            evidence_str = json.dumps(ev_dict, ensure_ascii=False)
            cursor.execute("""

            INSERT OR REPLACE INTO findings (id, task_id, category, title, severity, url, param, evidence, impact, remediation, verified, cvss_score, status, src_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f["id"], self.task_id, f["category"], f["title"], f["severity"],
                f["url"], f.get("param", ""), evidence_str, f["impact"], f["remediation"],
                f.get("verified", 0), f.get("cvss_score", 0.0), f.get("status", "OPEN"),
                f.get("src_type", "BASELINE_HYGIENE"), now
            ))

            
        # 2. 构造结构化资产拓扑地图
        assets_list = []
        for p in pages:
            assets_list.append({
                "url": p["url"],
                "title": p.get("title", ""),
                "status": p.get("status"),
                "type": "PAGE",
                "depth": p.get("depth", 0)
            })
        for api in api_endpoints:
            assets_list.append({
                "url": api,
                "title": "API 接口端点",
                "status": None,
                "type": "API",
                "depth": 1,
                "discovery_state": "DISCOVERED"
            })
        for st in static_assets:
            assets_list.append({
                "url": st,
                "title": "静态资源文件",
                "status": None,
                "type": "STATIC",
                "depth": 1,
                "discovery_state": "DISCOVERED"
            })
        for ext in external_links:
            assets_list.append({
                "url": ext,
                "title": "外部引用链接",
                "status": None,
                "type": "EXTERNAL",
                "depth": 1,
                "discovery_state": "DISCOVERED_NOT_VISITED"
            })

        # 3. 写入 baselines 快照
        baseline_id = str(uuid.uuid4())
        dom_hashes = {p["url"]: p["dom_hash"] for p in pages if "url" in p and "dom_hash" in p}
        finding_fingerprints = [
            f"{f.get('category', '')}|{f.get('title', '')}|{FindingVerifier.normalize_url(f.get('url', ''))}|{f.get('param', '')}"
            for f in findings
        ]
        findings_hash = hashlib.sha256("\n".join(sorted(finding_fingerprints)).encode("utf-8")).hexdigest()
        
        cursor.execute("""
        INSERT INTO baselines (id, target_url, task_id, snapshot_time, pages_count, assets_json, dom_hashes_json, findings_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            baseline_id, self.task_data["target_url"], self.task_id, now,
            len(pages), json.dumps(assets_list, ensure_ascii=False),
            json.dumps(dom_hashes, ensure_ascii=False), findings_hash
        ))
        
        # 4. 写入子资产快照 (任务3新增)
        sub_assets = crawl_results.get("sub_assets", [])
        if sub_assets:
            sub_asset_snapshot_id = str(uuid.uuid4())
            port_results = summary.get("port_scan_results", [])
            cursor.execute("""
            INSERT INTO sub_asset_snapshots (id, target_url, task_id, snapshot_time, sub_assets_count, sub_assets_json, port_results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                sub_asset_snapshot_id, self.task_data["target_url"], self.task_id, now,
                len(sub_assets), json.dumps(sub_assets, ensure_ascii=False), json.dumps(port_results, ensure_ascii=False)
            ))

        conn.commit()
        conn.close()

