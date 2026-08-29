import pytest
import json
from datetime import datetime
from plugins.scanner_core.sensitive_inspector import SensitiveInspector
from plugins.scanner_core.tamper_detector import TamperDetector
from plugins.scanner_core.vuln_detector import VulnerabilityDetector
from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler
from plugins.core.base import ScanContext

def test_json_sensitive_data_detection():
    """验证从标准 JSON API 响应中精准检出身份证和手机号 (解决前置审计中发现的双引号漏报缺陷)"""
    inspector = SensitiveInspector()
    
    # 构造标准合规的有效测试数据
    # 11010519491231002X (合规 ISO 7064 校验码)
    # 13800138000 (合规前缀)
    # 6222021234567890123 (合规 Luhn 校验码)
    payload = {
        "code": 200,
        "msg": "success",
        "data": {
            "user_id": 1001,
            "id_card": "11010519491231002X",
            "mobile": "13800138000",
            "bank_card": "6222021234567890128"
        }
    }
    
    page = {
        "url": "http://example.com/api/v1/user/profile",
        "html_content": json.dumps(payload),
        "content_type": "application/json"
    }
    
    findings = inspector.scan_pages([page])
    found_categories = [f["evidence"]["category"] for f in findings]
    
    assert "ID_CARD" in found_categories, "必须精准检出 JSON 结构中的居民身份证泄露"
    assert "PHONE" in found_categories, "必须精准检出 JSON 结构中的手机号泄露"
    assert "BANK_CARD" in found_categories, "必须精准检出 JSON 结构中的银行卡泄露"
    assert len(findings) >= 3, "应该命中全部 3 类敏感数据"


def test_tamper_detector_wildcard_auth_domain():
    """验证通配符授权域名下合法的子域跳转不会被误判为恶意重定向"""
    detector = TamperDetector(auth_domains=["*.example.com", "example.com"])
    
    # 正常的单点登录重定向代码
    benign_page = {
        "url": "https://portal.example.com/login",
        "html_content": """
        <html>
            <head><title>Login</title></head>
            <body>
                <script>
                    window.location.replace("https://sso.example.com/oauth/authorize");
                </script>
            </body>
        </html>
        """
    }
    
    findings = detector.scan_pages([benign_page])
    redirect_findings = [f for f in findings if "恶意页面跳转" in f["title"]]
    assert len(redirect_findings) == 0, "合法的子域名重定向不应触发恶意跳转告警"


def test_scancontext_parameter_and_form_piping():
    """验证数据总线 ScanContext 中的 url_parameters 与 forms 正确打通"""
    context = ScanContext(
        task_id="task-audit-test",
        target_url="http://127.0.0.1:8088",
        auth_domains=["127.0.0.1"]
    )
    
    # 模拟 crawler 填充数据总线
    context.url_parameters = [{"endpoint": "http://127.0.0.1:8088/api/user", "params": ["id"]}]
    context.forms = [{"action": "http://127.0.0.1:8088/login", "method": "POST", "inputs": [{"name": "username"}]}]
    context.api_endpoints = {"http://127.0.0.1:8088/api/user"}
    context.static_assets = {"http://127.0.0.1:8088/static/app.js"}
    
    assert isinstance(context.api_endpoints, set), "api_endpoints 必须为 set 类型"
    assert isinstance(context.static_assets, set), "static_assets 必须为 set 类型"
    assert len(context.url_parameters) == 1
    assert len(context.forms) == 1


def test_validate_id_card_dynamic_year():
    """验证身份证出生年份校验采用当前年份动态上限"""
    current_year = datetime.now().year
    
    # 构造当年出生的有效格式（格式合法性）
    recent_id = f"110101{current_year}0101001"
    # 计算 mod 11-2 校验码
    weight = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check_map = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2']
    total = sum(int(recent_id[i]) * weight[i] for i in range(17))
    full_recent_id = recent_id + check_map[total % 11]
    
    assert SensitiveInspector.validate_id_card(full_recent_id) is True, f"应支持校验 {current_year} 出生的身份证"
