import logging
import re
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("das_sentinel.verifier")

class FindingVerifier:
    """智能去重、多维证据关联、风险定级与非破坏性复测引擎"""

    @staticmethod
    def normalize_url(url: str) -> str:
        """标准化 URL：去除常见随机噪点参数 (时间戳, 随机数, Session Token) 以便精准去重"""
        try:
            parsed = urlparse(url.strip())
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            # 过滤动态时间戳与会话参数
            noise_keys = {'_', 't', 'time', 'timestamp', '_t', 'random', 'phpsessid', 'jsessionid', 'sid', 'token'}
            clean_params = {k: sorted(v) for k, v in query_params.items() if k.lower() not in noise_keys}
            
            clean_query = urlencode(clean_params, doseq=True)
            clean_path = parsed.path.rstrip('/') or '/'
            return urlunparse((parsed.scheme, parsed.netloc.lower(), clean_path, '', clean_query, ''))
        except Exception:
            return url.strip()

    @staticmethod
    def classify_src_standard(finding: Dict[str, Any]) -> Dict[str, Any]:
        """按头部 SRC (如阿里/腾讯/携程/字节 SRC) 漏洞收录与奖励标准进行严格仲裁分类"""
        cat = finding.get("category", "")
        title = (finding.get("title", "") or "").lower()
        sev = finding.get("severity", "LOW").upper()
        
        # 1. 行业 SRC 明确收录的【高价值实战漏洞】(SRC Exploitable Findings)
        # 满足条件：能造成实际破坏、获取敏感数据、接管主机、控制业务或绕过核心鉴权
        is_high_value_type = any(k in title for k in [
            "sql", "注入", "sqli", "ssti", "模板", "命令注入", "command", "rce", "代码执行",
            "文件读取", "路径穿越", "lfi", "path traversal", "bola", "idor", "越权", "未授权",
            "xss", "跨站脚本", "ssrf", "请求伪造", "挖矿", "后门", "暗链", "篡改", "涂鸦", "defacement",
            "coinhive", "eval(", ".env", "backup.sql", ".git", "源代码", "源码泄露", "source code", "身份证", "银行卡", "accesskey",
            "数据库连接串", "jwt", "cors", "跨域"
        ])
        has_real_evidence = bool(finding.get("verified") and finding.get("evidence"))

        if is_high_value_type and has_real_evidence:
            finding["src_type"] = "SRC_EXPLOITABLE"
            finding["src_status"] = "ACCEPTED_BY_SRC"
            finding["src_label"] = "🎯 SRC 有效实战漏洞"
            finding["src_reason"] = "具备确凿危害证明与利用链路，符合 SRC 中/高/严重漏洞收录与奖励标准"
            finding["confidence_status"] = "CONFIRMED"
        elif is_high_value_type:
            finding["src_type"] = "SRC_SUSPECTED"
            finding["src_status"] = "REQUIRES_REVIEW"
            finding["src_label"] = "⚠️ 疑似实战风险"
            finding["src_reason"] = "风险类型具备潜在危害，但当前证据不足，不能标记为已确认或直接用于 SRC 提报"
            finding["confidence_status"] = "SUSPECTED"
        else:
            # 2. 属于【安全配置基线/行业合规项】(Baseline Hygiene)
            finding["src_type"] = "BASELINE_HYGIENE"
            finding["src_status"] = "BASELINE_ONLY"
            finding["src_label"] = "📋 安全基线与合规建议"
            finding["src_reason"] = "属于 HTTP 响应头或协议基线配置，按 SRC 标准通常不作为独立漏洞收录，建议作为纵深防御基线加固"
            finding["confidence_status"] = "INFORMATIONAL" if sev in ("LOW", "INFO") else "SUSPECTED"
            
        return finding

    @classmethod
    def deduplicate_findings(cls, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """基于 (分类 + 漏洞特征指纹 + 标准化 URL + 注入参数) 进行智能特征去重与聚类"""
        seen_keys = {}
        deduped = []
        
        for f in findings:
            # 注入 SRC 仲裁标签
            f = cls.classify_src_standard(f)
            
            category = f.get("category", "")
            title = f.get("title", "")
            raw_url = f.get("url", "")
            param = f.get("param", "")
            
            norm_url = cls.normalize_url(raw_url)
            feature_key = f"{category}|{title}|{norm_url}|{param}"
            
            if feature_key not in seen_keys:
                f["instance_count"] = 1
                seen_keys[feature_key] = len(deduped)
                deduped.append(f)
            else:
                # 聚合同类风险实例数
                existing_idx = seen_keys[feature_key]
                deduped[existing_idx]["instance_count"] = deduped[existing_idx].get("instance_count", 1) + 1
                
        logger.info(f"Deduplicated findings from {len(findings)} to {len(deduped)} (Aggregated duplicates)")
        return deduped

    @classmethod
    def calculate_risk_summary(cls, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """计算风险评级分布与主机综合安全态势分 (按 SRC 标准与全量基线双维度)"""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "TOTAL": len(findings)
        }
        category_counts = {
            "VULN": 0,
            "SENSITIVE": 0,
            "TAMPER": 0,
            "ASSET": 0
        }
        src_counts = {
            "SRC_EXPLOITABLE": 0,
            "SRC_SUSPECTED": 0,
            "BASELINE_HYGIENE": 0,
            "SRC_CRITICAL": 0,
            "SRC_HIGH": 0,
            "SRC_MEDIUM": 0,
            "SRC_LOW": 0
        }
        
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            cat = f.get("category", "VULN").upper()
            src_type = f.get("src_type", "BASELINE_HYGIENE")
            
            if sev in counts:
                counts[sev] += 1
            if cat in category_counts:
                category_counts[cat] += 1
                
            if src_type == "SRC_EXPLOITABLE":
                src_counts["SRC_EXPLOITABLE"] += 1
                if sev == "CRITICAL": src_counts["SRC_CRITICAL"] += 1
                elif sev == "HIGH": src_counts["SRC_HIGH"] += 1
                elif sev == "MEDIUM": src_counts["SRC_MEDIUM"] += 1
                elif sev == "LOW": src_counts["SRC_LOW"] += 1
            elif src_type == "SRC_SUSPECTED":
                src_counts["SRC_SUSPECTED"] += 1
            else:
                src_counts["BASELINE_HYGIENE"] += 1
                
        # 安全评分模型 (基准100分，依据实战隐患与基线扣分)
        penalty = (
            counts["CRITICAL"] * 25 +
            counts["HIGH"] * 10 +
            counts["MEDIUM"] * 4 +
            counts["LOW"] * 1
        )
        security_score = max(0, 100 - penalty)
        
        if security_score >= 85:
            status_level = "HEALTHY (安全状态良好)"
        elif security_score >= 60:
            status_level = "WARNING (存在中高安全隐患)"
        else:
            status_level = "DANGER (面临严重安全威胁)"
            
        return {
            "severity_counts": counts,
            "category_counts": category_counts,
            "src_counts": src_counts,
            "security_score": security_score,
            "status_level": status_level,
            "src_assessment": {
                "has_src_vulnerabilities": src_counts["SRC_EXPLOITABLE"] > 0,
                "src_exploitable_total": src_counts["SRC_EXPLOITABLE"],
                "src_suspected_total": src_counts["SRC_SUSPECTED"],
                "src_high_risk_total": src_counts["SRC_CRITICAL"] + src_counts["SRC_HIGH"],
                "baseline_hygiene_total": src_counts["BASELINE_HYGIENE"]
            }
        }


    @classmethod
    async def retest_single_finding(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """针对单条风险记录执行即时非破坏性复测"""
        url = finding.get("url", "")
        category = finding.get("category", "")
        title = finding.get("title", "")
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8.0), trust_env=False) as session:
                # 复测不跟随跨域重定向，避免把授权范围扩展到第三方站点。
                async with session.get(url, allow_redirects=False) as resp:
                    status_code = resp.status
                    body = await resp.content.read(1024 * 1024 + 1)
                    body_truncated = len(body) > 1024 * 1024
                    text = body[:1024 * 1024].decode(resp.charset or "utf-8", errors="replace")
                    headers = dict(resp.headers)

                    if 300 <= status_code < 400:
                        return {
                            "retested": False,
                            "is_still_vulnerable": None,
                            "status_suggested": finding.get("status", "OPEN"),
                            "reason": f"目标返回 HTTP {status_code} 重定向；为保持授权边界未跟随，无法判断是否已修复",
                            "http_status": status_code,
                        }
                    if body_truncated:
                        return {
                            "retested": False,
                            "is_still_vulnerable": None,
                            "status_suggested": finding.get("status", "OPEN"),
                            "reason": "响应超过复测大小上限，未据截断内容下结论",
                            "http_status": status_code,
                        }
                    
                    is_still_vulnerable = False
                    reason = ""
                    
                    if category == "VULN":
                        if ".git" in url or ".env" in url or "backup.sql" in url:
                            if status_code == 200 and ("ref:" in text or "APP_KEY" in text or "CREATE TABLE" in text):
                                is_still_vulnerable = True
                                reason = "敏感文件仍可正常 200 访问并包含有效内容"
                            else:
                                is_still_vulnerable = False
                                reason = f"敏感文件已无法访问 (HTTP {status_code})"
                        elif "HSTS" in title:
                            is_still_vulnerable = "strict-transport-security" not in {k.lower(): v for k, v in headers.items()}
                            reason = "响应头中仍缺失 Strict-Transport-Security" if is_still_vulnerable else "已检测到 HSTS 响应头"
                        else:
                            is_still_vulnerable = status_code == 200
                            reason = f"页面状态码为 {status_code}"
                    elif category == "SENSITIVE":
                        evidence = finding.get("evidence", {})
                        masked_val = evidence.get("matched_value_masked", "")
                        # 检查原始明文是否还在页面中
                        rule_cat = evidence.get("category", "KEYWORD")
                        from plugins.scanner_core.sensitive_inspector import SensitiveInspector
                        inspector = SensitiveInspector()
                        findings_res = inspector.scan_pages([{"url": url, "html_content": text}])
                        is_still_vulnerable = any(f["title"] == title for f in findings_res)
                        reason = "页面中仍可提取到匹配的敏感隐私字段" if is_still_vulnerable else "页面已完成敏感数据脱敏或删除"
                    elif category == "TAMPER":
                        from plugins.scanner_core.tamper_detector import TamperDetector
                        tamper_detector = TamperDetector(auth_domains=[])
                        tamper_res = tamper_detector.scan_pages([{"url": url, "html_content": text}])
                        is_still_vulnerable = any(f["title"] == title for f in tamper_res)
                        reason = "页面仍存在暗链或篡改痕迹" if is_still_vulnerable else "暗链或恶意脚本已彻底清理"
                    else:
                        is_still_vulnerable = False
                        reason = "复测未检出异常"
                        
                    return {
                        "retested": True,
                        "is_still_vulnerable": is_still_vulnerable,
                        "status_suggested": "OPEN" if is_still_vulnerable else "FIXED",
                        "reason": reason,
                        "http_status": status_code
                    }
        except Exception as e:
            return {
                "retested": False,
                "is_still_vulnerable": None,
                "status_suggested": finding.get("status", "OPEN"),
                "reason": f"复测失败，无法判断是否已修复: {str(e)}",
                "http_status": 0
            }
