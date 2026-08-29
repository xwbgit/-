from bs4 import BeautifulSoup
from plugins.scanner_core.tamper_detector import TamperDetector

def test_hidden_link_detection():
    detector = TamperDetector(auth_domains=["example.gov.cn"])
    
    html = """
    <html>
    <body>
        <a href="/normal.html">正常链接</a>
        <div style="display:none;">
            <a href="https://www.macau-casino.com">澳门金沙博彩</a>
        </div>
        <a href="https://www.pk10.vip" style="position:absolute; left:-9999px;">六合彩特码</a>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    findings = detector._detect_hidden_and_malicious_links(soup, "http://example.gov.cn")
    
    assert len(findings) >= 2
    titles = [f["title"] for f in findings]
    assert any("隐蔽暗链" in t for t in titles)
    assert any("父容器样式 display:none" in t for t in titles)

def test_defacement_detection():
    detector = TamperDetector(auth_domains=["example.gov.cn"])
    html = "<html><body><h1>Hacked by ShadowSec 2026</h1><p>Welcome to online casino</p></body></html>"
    soup = BeautifulSoup(html, "html.parser")
    findings = detector._detect_defacement(html, soup, "http://example.gov.cn")
    
    assert len(findings) >= 1
    assert any("页面被黑客篡改涂鸦" in f["title"] for f in findings)
