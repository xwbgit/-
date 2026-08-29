import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from plugins.scanner_extensions.sub_assets.sub_asset_expander import SubAssetExpander

def test_root_domain_extraction():
    # 测试标准域名
    expander = SubAssetExpander(target_url="http://www.example.com")
    assert expander.root_domain == "example.com"
    
    # 测试多级政企与国家顶级域名 (.gov.cn, .com.cn)
    expander_gov = SubAssetExpander(target_url="https://oa.city-data.gov.cn:8443/login")
    assert expander_gov.root_domain == "city-data.gov.cn"
    
    expander_cn = SubAssetExpander(target_url="https://api.test.company.com.cn/v1")
    assert expander_cn.root_domain == "company.com.cn"
    
    # 测试本地回环地址
    expander_local = SubAssetExpander(target_url="http://127.0.0.1:8088")
    assert expander_local.root_domain == "127.0.0.1"


def test_passive_subdomain_extraction_from_content():
    expander = SubAssetExpander(
        target_url="https://portal.example.com",
        auth_domains=["example.com", "*.example.com"]
    )
    
    pages_data = [
        {
            "html_content": '<div>欢迎访问 <a href="https://sso.example.com/login">SSO登录</a>，接口位于 https://api.example.com/v1</div>',
            "headers": {"Content-Security-Policy": "default-src 'self' cdn.example.com;"}
        }
    ]
    js_scripts = [
        {
            "content": 'const devApi = "https://dev.example.com/api"; const adminPortal = "https://admin.example.com";'
        }
    ]
    external_links = [
        "https://oss.example.com/bucket/file.zip",
        "https://www.baidu.com" # 排除外部非授权域名
    ]
    
    extracted = expander.passive_extract_from_crawled_content(pages_data, js_scripts, external_links)
    
    assert "sso.example.com" in extracted
    assert "api.example.com" in extracted
    assert "cdn.example.com" in extracted
    assert "dev.example.com" in extracted
    assert "admin.example.com" in extracted
    assert "oss.example.com" in extracted
    assert "www.baidu.com" not in extracted


def test_sub_asset_role_classification():
    expander = SubAssetExpander(target_url="https://example.com")
    
    sso_role = expander._classify_sub_asset_role("sso.example.com", "统一身份认证")
    assert sso_role["category"] == "AUTH_SSO"
    assert sso_role["icon"] == "🔑"
    
    api_role = expander._classify_sub_asset_role("api-gw.example.com", "API Gateway")
    assert api_role["category"] == "API_GATEWAY"
    
    admin_role = expander._classify_sub_asset_role("oa.example.com", "协同办公系统")
    assert admin_role["category"] == "ADMIN_PORTAL"
    
    dev_role = expander._classify_sub_asset_role("stage.example.com", "预发布测试环境")
    assert dev_role["category"] == "DEV_TEST"
    
    cdn_role = expander._classify_sub_asset_role("cdn.example.com", "静态资源分发")
    assert cdn_role["category"] == "STATIC_CDN"


def test_subdomain_takeover_detection():
    expander = SubAssetExpander(target_url="https://example.com")
    
    # 模拟指向已废弃 GitHub Pages 的 CNAME 悬挂
    cnames = ["myproject.github.io"]
    body = "404: There isn't a GitHub Pages site here."
    
    risk = expander._check_takeover_risk(cnames, body, 404)
    assert risk is not None
    assert risk["vulnerable"] is True
    assert risk["service"] == "GitHub Pages"


def test_sub_asset_expander_end_to_end_mock():
    async def _async_test():
        expander = SubAssetExpander(
            target_url="https://test.example.com",
            auth_domains=["example.com", "*.example.com"]
        )
        
        pages = [
            {"html_content": 'API Gateway at https://api.example.com', "headers": {}}
        ]
        
        async def fake_probe(hostname):
            return {
                "hostname": hostname,
                "url": f"https://{hostname}",
                "status": 200,
                "visited": True,
                "discovery_state": "VISITED",
                "ownership_confirmed": True
            }

        with patch.object(expander, "_probe_subdomain_web", side_effect=fake_probe):
            results = await expander.expand_and_probe_all(pages_data=pages)
        
        assert results["root_domain"] == "example.com"
        assert results["active_sub_assets_count"] >= 1
        assert any(s["hostname"] == "api.example.com" for s in results["sub_assets"])
        assert "nodes" in results["topology_cluster"]

    asyncio.run(_async_test())

def test_crt_sh_and_wildcard_dns():
    async def _async_test():
        expander = SubAssetExpander(
            target_url="https://test.example.com",
            auth_domains=["example.com", "*.example.com"]
        )
        
        # Test crt.sh mock
        with patch("aiohttp.ClientSession.get") as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=[
                {"name_value": "secret.example.com\n*.example.com"},
                {"name_value": "mail.example.com"}
            ])
            mock_get.return_value.__aenter__.return_value = mock_resp
            
            extracted = await expander._query_crt_sh()
            assert "secret.example.com" in extracted
            assert "mail.example.com" in extracted

        # Test Directory Listing vulnerability finding
        sub_asset_mock = {
            "hostname": "files.example.com",
            "url": "http://files.example.com",
            "status": 200,
            "title": "Index of /backup/",
            "category": "STATIC_CDN",
            "role": "Static Assets",
            "ips": ["1.1.1.1"]
        }
        expander._evaluate_sub_asset_risks(sub_asset_mock, "<html><head><title>Index of /backup/</title></head>...</html>")
        
        dirlist_finding = next((f for f in expander.risk_findings if f["id"] == "sub-risk-dirlist-files.example.com"), None)
        assert dirlist_finding is not None
        assert dirlist_finding["severity"] == "HIGH"
        assert "目录遍历" in dirlist_finding["title"]

    asyncio.run(_async_test())


def test_secondary_crawl_linked():
    from plugins.core.base import ScanContext
    import plugins.scanner_extensions.sub_assets.sub_asset_expander as sub_asset_expander
    from plugins.scanner_extensions.sub_assets.asset_crawler import AssetCrawler

    async def _async_test():
        expander = SubAssetExpander(
            target_url="https://example.com",
            auth_domains=["example.com", "*.example.com"]
        )
        
        async def fake_probe(hostname):
            return {
                "hostname": hostname,
                "url": f"https://{hostname}",
                "status": 200,
                "visited": True,
                "discovery_state": "VISITED",
                "ownership_confirmed": True
            }

        with patch.object(expander, "_probe_subdomain_web", side_effect=fake_probe):
            with patch("plugins.scanner_extensions.sub_assets.asset_crawler.AssetCrawler") as MockCrawler:
                mock_crawler_instance = AsyncMock()
                mock_crawler_instance.crawl = AsyncMock(return_value={
                    "pages": [{"url": "https://api.example.com/v1/users"}]
                })
                MockCrawler.return_value = mock_crawler_instance
                
                context = ScanContext(task_id="test", target_url="https://example.com", auth_domains=["example.com", "*.example.com"])
                context.crawled_pages = [{"url": "https://example.com/"}]
                
                with patch.object(expander, "passive_extract_from_crawled_content", return_value={"api.example.com"}):
                    await expander.run(context)
                
                assert len(context.crawled_pages) == 2
                assert context.crawled_pages[1]["url"] == "https://api.example.com/v1/users"
                MockCrawler.assert_called_once()
                args, kwargs = MockCrawler.call_args
                assert kwargs["base_url"] == "https://api.example.com"
                assert kwargs["max_depth"] == 2
                assert kwargs["max_pages"] == 15

    asyncio.run(_async_test())
