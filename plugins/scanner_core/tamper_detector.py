from plugins.core.base import BaseScanner, ScanContext
import re
import uuid
import logging
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse

logger = logging.getLogger("das_sentinel.tamper")

class TamperDetector(BaseScanner):
    """页面篡改、暗链与恶意外链/挂马检测引擎"""

    def __init__(self, auth_domains: List[str]):
        self.auth_domains = set(d.strip().lower() for d in auth_domains if d.strip())
        
        # 常见黑产、博彩、色情、诈骗与恶意外链关键词与域名特征 (严谨黑产特征组合，杜绝误伤正常地名/旅游产品)
        self.malicious_domain_patterns = [
            r"bet\d{2,}\.com", r"casino\d*\.com", r"xpj\d+\.com", r"999\w+\.com", r"hg\d+\.com",
            r"amjs\d+\.com", r"bjl\d+\.com", r"pk10\w*\.com", r"cp\d+\.vip", r"lottery\d+\.com",
            r"6合彩", r"六合彩特码", r"澳门金沙娱乐", r"新葡京娱乐", r"博彩直营", r"现金棋牌", r"真人视讯",
            r"xvideos\.com", r"pornhub\.com", r"jav\w+\.com", r"sexy\w+\.com", r"ag\d+\.com"
        ]
        
        # 页面被黑/篡改典型特征 (增加上下文边界排除)
        self.defacement_signatures = [
            (r"hacked\s+by\s+[\w\d_\-\.]+", "页面被黑客篡改涂鸦 (Hacked by 标语)", "CRITICAL", 9.5),
            (r"(?:香港六合彩|澳门金沙娱乐城|博彩直营|现金棋牌提现|特码大曝光|在线百家乐投注)", "政企页面被植入博彩黑产违规内容", "HIGH", 8.8),
            (r"(?:代开增值税发票|办理假证|枪支弹药购买|迷奸药水|私家侦探定位)", "非法灰黑产违法信息篡改植入", "HIGH", 8.5)
        ]
        
        # 构建安全域名正则白名单 (支持 *.domain.com 通配符)
        domain_patterns = []
        for d in self.auth_domains:
            clean_d = d.lstrip("*.")
            if clean_d:
                domain_patterns.append(r"(?:[a-zA-Z0-9-]+\.)*" + re.escape(clean_d))
        domain_regex_part = "|".join(domain_patterns) if domain_patterns else r"[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

        # 恶意外链与挖矿挂马脚本特征
        self.malicious_script_signatures = [
            (r"coinhive\.min\.js|cryptoloot|miner\.start|webassembly.*miner", "网页被植入 Web 挖矿脚本 (Coinhive/CryptoLoot)", "HIGH", 8.0),
            (r"eval\s*\(\s*unescape\s*\(\s*['\"][^'\"]{20,}", "高度混淆的 eval(unescape(...)) 恶意挂马脚本", "HIGH", 8.5),
            (r"document\.write\s*\(\s*unescape\s*\(\s*['\"][^'\"]{20,}", "document.write 动态恶意脚本释放载荷", "HIGH", 8.2),
            (rf"window\.location\.replace\s*\(\s*['\"]https?:\/\/(?!(?:{domain_regex_part}))", "恶意页面跳转与流量劫持注入", "HIGH", 8.0)
        ]

    def scan_pages(self, pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for page in pages:
            url = page.get("url", "")
            html = page.get("html_content", "")
            if not html:
                continue
                
            soup = BeautifulSoup(html, "html.parser")
            
            # 1. 恶意外链与暗链检测 (Hidden Links)
            hidden_link_findings = self._detect_hidden_and_malicious_links(soup, url)
            findings.extend(hidden_link_findings)
            
            # 2. 页面被黑与内容篡改 (Defacement)
            defacement_findings = self._detect_defacement(html, soup, url)
            findings.extend(defacement_findings)
            
            # 3. 恶意挂马与挖矿脚本 (Malicious Scripts)
            script_findings = self._detect_malicious_scripts(html, soup, url)
            findings.extend(script_findings)
            
        return findings

    def _is_same_or_auth_domain(self, href: str, base_url: str) -> bool:
        """判断链接是否属于本站或已授权安全域名"""
        try:
            parsed_href = urlparse(href)
            if parsed_href.scheme and parsed_href.scheme not in ("http", "https"):
                return False
            if not parsed_href.netloc:
                return True # 相对路径属于本站
            netloc = parsed_href.netloc.lower().split(':')[0]
            base_netloc = urlparse(base_url).netloc.lower().split(':')[0]
            if netloc == base_netloc or netloc.endswith("." + base_netloc):
                return True
            for auth in self.auth_domains:
                if netloc == auth or netloc.endswith("." + auth):
                    return True
            return False
        except Exception:
            return True

    def _detect_hidden_and_malicious_links(self, soup: BeautifulSoup, url: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 遍历所有 a 标签
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href", "").strip()
            if not href or href.startswith("javascript:") or href == "#":
                continue

            text = a_tag.get_text().strip()
            
            # 排除无障碍辅助朗读标签与合法下拉框菜单
            if a_tag.get("assist-speak-text") or a_tag.get("aria-hidden") == "true" or "sr-only" in " ".join(a_tag.get("class", [])):
                continue

            is_internal = self._is_same_or_auth_domain(href, url)

            # 检测暗链 (仅当隐藏链接指向外部未知域名或包含黑产词时才告警，避免误伤前端下拉菜单/Tab)
            is_hidden = False
            hidden_reason = ""
            hidden_node = a_tag
            styled_nodes = [(a_tag, "链接自身")]
            styled_nodes.extend((parent, "父容器") for parent in list(a_tag.parents)[:3])
            for node, source in styled_nodes:
                style = str(node.get("style", "")).lower().replace(" ", "") if hasattr(node, "get") else ""
                if "display:none" in style:
                    is_hidden, hidden_reason, hidden_node = True, f"{source}样式 display:none 隐藏", node
                elif "visibility:hidden" in style:
                    is_hidden, hidden_reason, hidden_node = True, f"{source}样式 visibility:hidden 隐藏", node
                elif "font-size:0" in style:
                    is_hidden, hidden_reason, hidden_node = True, f"{source}字体大小为 0 像素隐藏", node
                elif "left:-" in style or "top:-999" in style or "margin-left:-999" in style:
                    is_hidden, hidden_reason, hidden_node = True, f"{source}利用负坐标偏离屏幕可视区域隐藏", node
                elif "opacity:0" in style:
                    is_hidden, hidden_reason, hidden_node = True, f"{source}透明度为 0 隐藏", node
                if is_hidden:
                    break
                
            if is_hidden and not is_internal:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "category": "TAMPER",
                    "title": f"页面检测到指向外部未授权站点的隐蔽暗链 ({hidden_reason})",
                    "severity": "HIGH",
                    "url": url,
                    "param": f"Target Href: {href}",
                    "evidence": {
                        "matched_snippet": str(a_tag)[:300],
                        "hidden_container_snippet": str(hidden_node)[:300],
                        "link_text": text,
                        "link_target": href,
                        "hidden_reason": hidden_reason
                    },
                    "impact": "网站常被黑客利用暗链进行黑帽 SEO 引流或私自挂载外部恶意站点",
                    "remediation": "立即清理页面中被非法植入的隐藏 <a> 标签代码，并排查网站发布系统及数据库权限",
                    "verified": 1,
                    "cvss_score": 7.5,
                    "status": "OPEN"
                })

            # 检测指向黑产博彩的恶意外链 (仅对外链检测，排除本站正常旅游地名/酒店业务)
            if not is_internal:
                for pattern in self.malicious_domain_patterns:
                    if re.search(pattern, href, re.IGNORECASE) or re.search(pattern, text, re.IGNORECASE):
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "category": "TAMPER",
                            "title": "页面存在涉黑产/博彩/违规恶意外链",
                            "severity": "HIGH",
                            "url": url,
                            "param": f"Malicious Href: {href}",
                            "evidence": {
                                "matched_snippet": str(a_tag)[:300],
                                "link_text": text,
                                "link_target": href,
                                "matched_pattern": pattern
                            },
                            "impact": "可能导致政企网站权威性受损、被监管机构通报或被搜索引擎降权拦截",
                            "remediation": "下线相关外链指向，检查是否有 CMS 模版注入漏洞或未授权编辑权限",
                            "verified": 1,
                            "cvss_score": 8.0,
                            "status": "OPEN"
                        })
                        break


        return findings

    def _detect_defacement(self, html: str, soup: BeautifulSoup, url: str) -> List[Dict[str, Any]]:
        findings = []
        page_text = soup.get_text()
        
        for pattern, title, severity, cvss in self.defacement_signatures:
            match = re.search(pattern, page_text, re.IGNORECASE)
            if match:
                snippet = match.group(0)
                findings.append({
                    "id": str(uuid.uuid4()),
                    "category": "TAMPER",
                    "title": title,
                    "severity": severity,
                    "url": url,
                    "param": "DOM Text Content",
                    "evidence": {
                        "matched_snippet": f"... {page_text[max(0, match.start()-30):min(len(page_text), match.end()+30)].strip()} ...",
                        "matched_word": snippet
                    },
                    "impact": "网站主页或栏目已被恶意篡改，直接破坏政企形象并产生严重合规风险",
                    "remediation": "立即切断外网访问，使用代码版本控制及备份还原页面内容，同时进行全面后门排查",
                    "verified": 1,
                    "cvss_score": cvss,
                    "status": "OPEN"
                })
        return findings

    def _detect_malicious_scripts(self, html: str, soup: BeautifulSoup, url: str) -> List[Dict[str, Any]]:
        findings = []
        
        # 扫描内联脚本及外部脚本引用
        for script_tag in soup.find_all("script"):
            script_src = script_tag.get("src", "")
            script_body = script_tag.get_text()
            target_content = script_src + " " + script_body
            
            for pattern, title, severity, cvss in self.malicious_script_signatures:
                match = re.search(pattern, target_content, re.IGNORECASE)
                if match:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "TAMPER",
                        "title": title,
                        "severity": severity,
                        "url": url,
                        "param": "Script Tag Payload",
                        "evidence": {
                            "matched_snippet": target_content[max(0, match.start()-20):min(len(target_content), match.end()+50)].strip(),
                            "script_src": script_src
                        },
                        "impact": "访问用户的浏览器将被利用进行未授权挖矿、被植入远控木马或发生重定向欺诈",
                        "remediation": "清除页面中的恶意 <script> 代码，配置严格的 CSP 策略 (script-src 'self')",
                        "verified": 1,
                        "cvss_score": cvss,
                        "status": "OPEN"
                    })
        return findings

    async def run(self, context: ScanContext) -> None:
        self.auth_domains = context.auth_domains
        findings = self.scan_pages(context.crawled_pages)
        context.add_findings(findings)
