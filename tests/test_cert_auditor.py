import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from plugins.scanner_extensions.sub_assets.cert_auditor import CertAuditor
import ssl
from datetime import datetime, timedelta, timezone

def test_cert_auditor_init():
    auditor = CertAuditor(timeout_sec=10.0, concurrency=10)
    assert auditor.timeout == 10.0
    assert auditor.concurrency == 10

def test_cert_expiration_check():
    auditor = CertAuditor()
    
    async def mock_open_connection(*args, **kwargs):
        writer = MagicMock()
        ssl_obj = MagicMock()
        writer.get_extra_info.return_value = ssl_obj
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        
        # Mock cert dictionary
        past_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
        ssl_obj.getpeercert.return_value = {
            "notAfter": past_date,
            "issuer": ((("organizationName", "Test Org"),),),
            "subject": ((("commonName", "test.example.com"),),)
        }
        ssl_obj.cipher.return_value = ("AES256-SHA", "TLSv1.2", 256)
        
        return MagicMock(), writer

    async def _run():
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await auditor.audit_host("test.example.com", 443)
            return result

    result = asyncio.run(_run())
    assert result is not None
    assert result["expired"] is True
    assert result["issuer"] == "Test Org"
    assert result["subject"] == "test.example.com"
    assert "证书已过期" in result["vulnerabilities"]
    assert result["tls_version"] == "TLSv1.2"
    assert result["weak_cipher"] is False

def test_cert_weak_cipher_and_tls():
    auditor = CertAuditor()
    
    async def mock_open_connection(*args, **kwargs):
        writer = MagicMock()
        ssl_obj = MagicMock()
        writer.get_extra_info.return_value = ssl_obj
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()
        
        future_date = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
        ssl_obj.getpeercert.return_value = {
            "notAfter": future_date,
        }
        # Weak cipher and old TLS
        ssl_obj.cipher.return_value = ("RC4-SHA", "TLSv1", 128)
        
        return MagicMock(), writer

    async def _run():
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await auditor.audit_host("test.example.com", 443)
            return result

    result = asyncio.run(_run())
    assert result is not None
    assert result["expired"] is False
    assert result["weak_cipher"] is True
    assert any("RC4-SHA" in v for v in result["vulnerabilities"])
    assert any("TLSv1" in v for v in result["vulnerabilities"])

def test_cert_mismatch():
    auditor = CertAuditor()

    call_count = 0
    async def mock_open_connection(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        
        if call_count == 1:
            # First call for insecure connection works
            writer = MagicMock()
            ssl_obj = MagicMock()
            writer.get_extra_info.return_value = ssl_obj
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            ssl_obj.getpeercert.return_value = {}
            ssl_obj.cipher.return_value = ("AES", "TLSv1.2", 256)
            return MagicMock(), writer
        elif call_count == 2:
            # Second call for secure connection raises mismatch
            raise ssl.CertificateError("hostname 'test.example.com' doesn't match")
            
    async def _run():
        with patch("asyncio.open_connection", side_effect=mock_open_connection):
            result = await auditor.audit_host("test.example.com", 443)
            return result

    result = asyncio.run(_run())
    assert result is not None
    assert result["mismatch"] is True
    assert any("证书域名不匹配" in v for v in result["vulnerabilities"])

def test_cert_run_integration():
    from plugins.core.base import ScanContext
    auditor = CertAuditor()
    
    async def mock_audit_host(host, port):
        return {
            "hostname": host,
            "port": port,
            "vulnerabilities": ["自签名或不可信证书", "使用老旧不安全的协议: TLSv1.1"],
            "tls_version": "TLSv1.1",
            "cipher_name": "AES128-SHA"
        }
        
    async def _run():
        context = ScanContext(task_id="test-task", target_url="https://example.com")
        context.sub_assets = [
            {"hostname": "dev.example.com", "ownership_confirmed": True, "scheme": "https"}
        ]
        
        with patch.object(auditor, "audit_host", side_effect=mock_audit_host):
            await auditor.run(context)
            
        assert len(context.findings) == 2
        assert "cert_audit_results" in context.metadata
        
    asyncio.run(_run())
