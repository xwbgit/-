from plugins.core.base import BaseScanner, ScanContext
import re
import uuid
import logging
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.sensitive")

class SensitiveInspector(BaseScanner):
    """深度敏感信息、个人隐私、云端秘钥与数据泄露检测引擎"""

    def __init__(self, custom_keywords: Optional[List[str]] = None):
        self.custom_keywords = [k.strip() for k in (custom_keywords or []) if k.strip()]
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, category, pattern, risk_level, description FROM sensitive_rules WHERE enabled = 1")
            rows = cursor.fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning(f"Error loading sensitive rules: {e}")
            return []

    @staticmethod
    def validate_id_card(id_str: str) -> bool:
        """校验 18 位中国居民身份证校验码 (ISO 7064:1983.MOD 11-2) 及合法出生日期与省份代码"""
        if len(id_str) != 18:
            return False
            
        # 排除全部相同或连号等假测试数据
        if len(set(id_str[:17])) <= 2:
            return False
            
        # 省份代码检查 (11-65)
        prov_code = int(id_str[:2])
        valid_provs = {11,12,13,14,15,21,22,23,31,32,33,34,35,36,37,41,42,43,44,45,46,50,51,52,53,54,61,62,63,64,65}
        if prov_code not in valid_provs:
            return False
            
        # 出生年份检查 (1920 - 当前年份)
        try:
            from datetime import datetime
            current_year = datetime.now().year
            year = int(id_str[6:10])
            month = int(id_str[10:12])
            day = int(id_str[12:14])
            if year < 1920 or year > current_year or month < 1 or month > 12 or day < 1 or day > 31:
                return False
        except ValueError:
            return False

        # Mod 11-2 校验码
        weight = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_map = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
        try:
            total = sum(int(id_str[i]) * weight[i] for i in range(17))
            return check_map[total % 11].upper() == id_str[17].upper()
        except ValueError:
            return False

    @staticmethod
    def validate_luhn(card_str: str) -> bool:
        """校验银行卡 Luhn 模 10 算法"""
        digits = [int(c) for c in card_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        if len(set(digits)) <= 2:  # 排除 1111111111111 等假卡号
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                checksum += (doubled - 9) if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    @staticmethod
    def validate_phone(phone_str: str) -> bool:
        """校验中国大陆 11 位手机号有效运营商前缀并过滤典型假号"""
        if len(phone_str) != 11 or not phone_str.startswith('1'):
            return False
        # 排除 13800000000, 18888888888 等示例假号
        if len(set(phone_str[3:])) <= 2 or phone_str.endswith('00000000') or phone_str.endswith('12345678'):
            return False
        # 合法号段前缀
        valid_prefix = {'130','131','132','133','134','135','136','137','138','139',
                        '145','147','149','150','151','152','153','155','156','157','158','159',
                        '166','170','171','172','173','175','176','177','178','180','181','182',
                        '183','184','185','186','187','188','189','191','193','195','198','199'}
        return phone_str[:3] in valid_prefix

    @staticmethod
    def mask_sensitive_value(val: str, category: str) -> str:
        """敏感数据脱敏掩码展示"""
        if not val or len(val) <= 4:
            return "****"
        if category == "ID_CARD" and len(val) == 18:
            return val[:6] + "********" + val[14:]
        elif category == "PHONE" and len(val) == 11:
            return val[:3] + "****" + val[7:]
        elif category == "BANK_CARD" and len(val) >= 13:
            return val[:4] + "****" * ((len(val)-8)//4) + val[-4:]
        elif category == "SECRET_KEY":
            return val[:4] + "****************" + val[-4:] if len(val) > 10 else "********"
        else:
            return val[:2] + "****" + val[-2:]

    def scan_pages(self, pages: List[Dict[str, Any]], js_scripts: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        findings = []
        
        # 合并待扫描的资源单元 (页面 + JS 脚本)
        scan_units = []
        for p in pages:
            scan_units.append({"url": p.get("url", ""), "content": p.get("html_content", ""), "type": "HTML"})
        for js in (js_scripts or []):
            scan_units.append({"url": js.get("url", ""), "content": js.get("content", ""), "type": "JS"})

        for unit in scan_units:
            url = unit.get("url", "")
            content = unit.get("content", "")
            if not content:
                continue
                
            # 提取纯文本与脚本内容
            if unit["type"] == "HTML":
                try:
                    soup = BeautifulSoup(content, "html.parser")
                    text_content = soup.get_text()
                except Exception:
                    text_content = content
            else:
                text_content = content
            
            # 1. 执行规则库扫描 (正则与模式匹配)
            for rule in self.rules:
                pattern = rule["pattern"]
                category = rule["category"]
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        matched_val = match.group(0)
                        
                        # 深度校验过滤误报
                        if category == "ID_CARD" and not self.validate_id_card(matched_val):
                            continue
                        if category == "BANK_CARD" and not self.validate_luhn(matched_val):
                            continue
                        if category == "PHONE" and not self.validate_phone(matched_val):
                            continue
                        if category == "KEYWORD" and ("email" in rule["name"].lower() or rule["id"] == "rule-email" or "@" in rule["pattern"]):
                            # 必须是完整的邮件地址格式：local@domain.tld
                            if not re.match(r'^[a-zA-Z0-9._%+\-]{2,64}@[a-zA-Z0-9.\-]{2,253}\.[a-zA-Z]{2,10}$', matched_val):
                                continue
                            # 排除图片/CSS/JS/示例域名
                            if any(ex in matched_val.lower() for ex in ["example.com", "test.com", "sample.com", "domain.com", "w3.org", "@2x", "@3x", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".css", ".js", "schematics", "noreply", "no-reply"]):
                                continue
                            # 排除在JSON/JS 字段内的值（支持带引号和不带引号的 key 格式）
                            prev_ctx = content[max(0, match.start()-100):match.start()].lower()
                            # 带引号的JSON key: "title": "email@..." 或不带引号的JS: {title: "email@..."}
                            if any(k in prev_ctx for k in [
                                '"title":', "'title':", 'title:',
                                '"url":', "'url':", 'url:',
                                '"label":', '"name":', "'name':", 'name:',
                                '"key":', '"route":', '"path":',
                                '"link":', '"href":',
                                # 排除 HTML 属性
                                'data-email=', 'placeholder=', 'value=',
                                # 排除 JS 变量赋值
                                'var ', 'const ', 'let ',
                            ]):
                                continue
                            # 排除截断的邮件地址（含星号的已脱敏值不是真实泄露）
                            if '****' in matched_val or '**' in matched_val:
                                continue
                            # 排除企业官方客服/联系邮件地址（不属于数据泄露）
                            _email_local = matched_val.split('@')[0].lower()
                            if _email_local in ('support', 'info', 'contact', 'admin', 'help',
                                                'service', 'webmaster', 'no-reply', 'noreply',
                                                'sales', 'feedback', 'abuse', 'security',
                                                'hello', 'team', 'press', 'legal', 'privacy'):
                                continue

                            # 排除开源组件库/第三方 JS 包的作者、贡献者与版权声明（典型误报）
                            surrounding_ctx = content[max(0, match.start() - 150):min(len(content), match.end() + 150)].lower()
                            if any(oss_kw in surrounding_ctx for oss_kw in [
                                "@author", "author:", "authors", "@copyright", "copyright",
                                "license", "licence", "@license", "mit license", "apache-2.0",
                                "contributor", "contributors", "maintainer", "packaged by",
                                "github.com", "npmjs.com", "webpack://", "rollup"
                            ]):
                                continue

                        # 🎯 关键防误报：排除静态资源构建版本戳、微服务 Trace ID、业务行程 ID、Webpack Chunk 与静态文件路径
                        start_pos = max(0, match.start() - 35)
                        end_pos = min(len(content), match.end() + 35)
                        raw_snippet = content[start_pos:end_pos].strip()

                        if category == "FILE_TYPE":
                            # 必须是实际可下载链接或文件 URL 路径，排除 JS 变量、模块导入及代码中的扩展名字符串
                            prev_50 = content[max(0, match.start() - 50):match.start()].lower()
                            if not any(k in prev_50 for k in ["href=", "src=", "http://", "https://", "download="]):
                                continue
                            # 排除常用的前端配置库名与构建文件
                            surrounding = content[max(0, match.start() - 40):min(len(content), match.end() + 40)].lower()
                            if any(k in surrounding for k in ["webpack", "vite", "babel", "tailwind", "postcss", "tsconfig", ".config.js", ".config.ts", "package.json"]):
                                continue

                        if category in ("BANK_CARD", "ID_CARD", "PHONE"):
                            # 1. 排除时间戳 (如 13 位 16xx/17xx 毫秒时间戳)
                            if matched_val.isdigit() and len(matched_val) == 13 and (matched_val.startswith('16') or matched_val.startswith('17') or matched_val.startswith('18') or matched_val.startswith('19')):
                                continue
                            # 2. 排除微服务调用链 ID、行程产品 ID、日志追踪 ID、订单 ID
                            prev_50 = content[max(0, match.start() - 50):match.start()].lower()
                            if any(k in prev_50 for k in ["tourinfoid", "trace_id", "traceid", "log_id", "logid", "spanid", "skuid", "productid", "packageid", "routeid", "orderid", "hotelid", "cityid", "districtid", "scene_", "flightid", "batchid", "versionid", "c13="]):
                                continue
                            # 3. 排除 HTML 属性 ID、CSS 选择器、静态文件引用路径与图片扩展名
                            if any(ext in raw_snippet.lower() for ext in [".css", ".js", ".png", ".jpg", ".svg", ".woff", ".webp", "href=", "src=", "url(", "/static/", "/assets/", "/chunk-", "/mfe_", "id=", "class=", "style=", "<style", "georedirect", "px", "rem", "d=\"m", "viewbox"]):
                                continue
                            # 4. 排除前后紧贴路径斜杠、连字符或文件扩展名点 (允许正常 JSON 属性与字符串引号)
                            prev_char = content[match.start() - 1] if match.start() > 0 else " "
                            next_char = content[match.end()] if match.end() < len(content) else " "
                            if prev_char in ("/", "\\", "-", "_", ".") or next_char in ("/", "\\", "-", "_", "."):
                                continue


                            
                        masked_val = self.mask_sensitive_value(matched_val, category)
                        masked_snippet = raw_snippet.replace(matched_val, masked_val)
                        
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "category": "SENSITIVE",
                            "title": f"页面暴露敏感信息: {rule['name']}",
                            "severity": rule["risk_level"],
                            "url": url,
                            "param": f"Rule: {rule['name']} ({category})",
                            "evidence": {
                                "matched_snippet": masked_snippet,
                                "matched_value_masked": masked_val,
                                "rule_id": rule["id"],
                                "category": category
                            },
                            "impact": f"违反《数据安全法》与《个人信息保护法》，造成【{rule['name']}】直接泄露风险",
                            "remediation": f"立即对页面或 API 返回中的敏感数据进行脱敏处理，移除未经授权公开的敏感字段",
                            "verified": 1,
                            "cvss_score": 7.8 if rule["risk_level"] in ("CRITICAL", "HIGH") else 5.0,
                            "status": "OPEN"
                        })

                except Exception as e:
                    logger.debug(f"Rule regex execution error on {rule['name']}: {e}")

            # 2. 扫描本单位临时录入的自定义关键词
            for kw in self.custom_keywords:
                if kw in text_content:
                    idx = text_content.find(kw)
                    snippet = text_content[max(0, idx-30):min(len(text_content), idx+len(kw)+30)].strip()
                    masked_kw = self.mask_sensitive_value(kw, "KEYWORD")
                    masked_snippet = snippet.replace(kw, masked_kw)
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "category": "SENSITIVE",
                        "title": f"命中自定义敏感关键词: 【{kw}】",
                        "severity": "HIGH",
                        "url": url,
                        "param": f"Keyword: {kw}",
                        "evidence": {
                            "matched_snippet": f"... {masked_snippet} ...",
                            "matched_value_masked": masked_kw
                        },
                        "impact": f"检测到包含本单位重要敏感标识或保密关键词【{kw}】的内容被公开发布",
                        "remediation": "核查该页面发布审批流程，删除或替换敏感业务关键词",
                        "verified": 1,
                        "cvss_score": 7.0,
                        "status": "OPEN"
                    })

        return findings

    async def run(self, context: ScanContext) -> None:
        self.custom_keywords = context.scan_scope.get('custom_sensitive_keywords', [])
        findings = self.scan_pages(context.crawled_pages, js_scripts=context.js_scripts)
        context.add_findings(findings)
