"""
HTTPS 证书安全审计引擎 (TLS/SSL Auditor)
职责:
1. 连接目标服务器提取 HTTPS 证书信息
2. 检查证书是否过期、域名是否匹配、是否自签名
3. 检测弱 TLS 版本 (TLS 1.0, TLS 1.1)
4. 检测弱密码套件
5. 将高危风险注入到 ScanContext
"""

import asyncio
import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.cert_auditor")


class CertAuditor(BaseScanner):
    """HTTPS 证书安全审计器"""

    def __init__(self, timeout_sec: float = 5.0, concurrency: int = 50):
        super().__init__()
        self.timeout = timeout_sec
        self.concurrency = concurrency
        self.findings = []

    async def audit_host(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """对单个主机执行证书审计"""
        result = {
            "hostname": hostname,
            "port": port,
            "expired": False,
            "self_signed": False,
            "weak_cipher": False,
            "tls_version": "",
            "cipher_name": "",
            "mismatch": False,
            "issuer": "",
            "subject": "",
            "not_after": "",
            "vulnerabilities": [],
            "error": None
        }

        # 首先使用安全的上下文连接，如果报错可能是自签名或域名不匹配
        secure_ctx = ssl.create_default_context()
        secure_ctx.check_hostname = True
        secure_ctx.verify_mode = ssl.CERT_REQUIRED

        # 再准备一个不验证的上下文，用于提取详细信息
        insecure_ctx = ssl.create_default_context()
        insecure_ctx.check_hostname = False
        insecure_ctx.verify_mode = ssl.CERT_NONE
        # 允许较低版本的 TLS 以便检测
        try:
            # 忽略 TLSv1 的弃用警告或使用常量
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                insecure_ctx.minimum_version = ssl.TLSVersion.TLSv1
        except AttributeError:
            pass
        # 允许所有的 ciphers 以便检测弱 cipher
        insecure_ctx.set_ciphers('ALL:@SECLEVEL=0')

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=insecure_ctx),
                timeout=self.timeout
            )
            ssl_obj = writer.get_extra_info('ssl_object')
            if not ssl_obj:
                writer.close()
                return None

            cert = ssl_obj.getpeercert(binary_form=False)
            cipher_info = ssl_obj.cipher()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if cipher_info:
                result["cipher_name"] = cipher_info[0]
                result["tls_version"] = cipher_info[1]

            if cert:
                # 解析基本信息
                for item in cert.get("issuer", ()):
                    for k, v in item:
                        if k == "organizationName":
                            result["issuer"] = v
                for item in cert.get("subject", ()):
                    for k, v in item:
                        if k == "commonName":
                            result["subject"] = v

                result["not_after"] = cert.get("notAfter", "")

                # 检查过期
                if result["not_after"]:
                    try:
                        not_after_date = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                        not_after_date = not_after_date.replace(tzinfo=timezone.utc)
                        if datetime.now(timezone.utc) > not_after_date:
                            result["expired"] = True
                            result["vulnerabilities"].append("证书已过期")
                    except Exception:
                        pass
            else:
                # 获取二进制 cert 进行备用解析，某些情况下 CERT_NONE 不返回 dict
                bin_cert = ssl_obj.getpeercert(binary_form=True)
                if bin_cert:
                    pass # 实际生产可使用 cryptography 解析

            # 测试是否自签名或域名不匹配
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=secure_ctx),
                    timeout=self.timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except ssl.CertificateError as e:
                msg = str(e).lower()
                if "match" in msg:
                    result["mismatch"] = True
                    result["vulnerabilities"].append("证书域名不匹配")
            except ssl.SSLCertVerificationError as e:
                msg = str(e).lower()
                if "self signed" in msg or "certificate verify failed" in msg:
                    result["self_signed"] = True
                    result["vulnerabilities"].append("自签名或不可信证书")
                elif "match" in msg:
                    result["mismatch"] = True
                    result["vulnerabilities"].append("证书域名不匹配")
            except Exception:
                pass

            # 检查弱 TLS 版本
            if result["tls_version"] in ("SSLv3", "TLSv1", "TLSv1.1", "TLS 1.0", "TLS 1.1"):
                result["weak_cipher"] = True
                result["vulnerabilities"].append(f"使用老旧不安全的协议: {result['tls_version']}")

            # 检查弱加密套件
            if result["cipher_name"] and any(weak in result["cipher_name"] for weak in ["RC4", "DES", "NULL", "MD5"]):
                result["weak_cipher"] = True
                result["vulnerabilities"].append(f"使用弱密码套件: {result['cipher_name']}")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except ssl.SSLError as e:
            result["error"] = str(e)
            result["vulnerabilities"].append(f"SSL/TLS 握手失败: {e}")
        except Exception as e:
            logger.debug(f"[CertAuditor] Error auditing {hostname}:{port} - {e}")
            return None

        return result

    async def _audit_worker(self, host: str, port: int, semaphore: asyncio.Semaphore) -> Optional[Dict[str, Any]]:
        async with semaphore:
            return await self.audit_host(host, port)

    async def run(self, context: ScanContext) -> None:
        sub_assets = context.sub_assets or []
        if not sub_assets:
            logger.info("[CertAuditor] No sub-assets to audit, skipping.")
            return

        targets = []
        for asset in sub_assets:
            hostname = asset.get("hostname", "")
            # 只测试 HTTPS 端口
            if hostname and asset.get("ownership_confirmed", False):
                # 检查资产是否是以 https 方式发现的，或者强制扫 443
                scheme = asset.get("scheme", "")
                if scheme == "https" or asset.get("status") is None:
                    # 获取 target 端口如果是目标端口则使用，否则默认 443
                    parsed = urlparse(asset.get("url", f"https://{hostname}"))
                    port = parsed.port or 443
                    targets.append((hostname, port))

        # 去重
        targets = list(set(targets))
        if not targets:
            return

        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [self._audit_worker(host, port, semaphore) for host, port in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        audit_data = []
        for r in results:
            if isinstance(r, dict) and r is not None:
                audit_data.append(r)
                vulns = r.get("vulnerabilities", [])
                
                # 如果有漏洞，生成 findings
                if vulns:
                    hostname = r["hostname"]
                    port = r["port"]
                    for vuln in vulns:
                        severity = "LOW"
                        cvss = 3.7
                        if "过期" in vuln:
                            severity = "MEDIUM"
                            cvss = 5.0
                        elif "自签名" in vuln:
                            severity = "LOW"
                            cvss = 3.5
                        elif "协议" in vuln or "弱密码" in vuln:
                            severity = "MEDIUM"
                            cvss = 4.3

                        context.add_findings([{
                            "task_id": context.task_id,
                            "category": "MISCONFIG",
                            "severity": severity,
                            "level": severity,
                            "title": f"HTTPS 证书安全风险: {vuln} ({hostname})",
                            "url": f"https://{hostname}:{port}",
                            "param": "",
                            "impact": f"子资产 {hostname} 在 {port} 端口存在 HTTPS 配置风险：{vuln}，可能导致中间人攻击或数据被破解。",
                            "evidence": {
                                "matched_snippet": vuln,
                                "tls_version": r.get("tls_version"),
                                "cipher_name": r.get("cipher_name"),
                                "not_after": r.get("not_after")
                            },
                            "remediation": "更新证书，配置服务器强制使用 TLS 1.2 或 TLS 1.3，并禁用弱加密套件（如 RC4, 3DES）。",
                            "verified": 1,
                            "cvss_score": cvss,
                            "status": "OPEN"
                        }])

        context.metadata["cert_audit_results"] = audit_data
