import logging
import aiohttp
import asyncio
import ipaddress
from typing import Dict, Any, List
from plugins.core.base import BaseScanner, ScanContext

logger = logging.getLogger("das_sentinel.whois_enricher")

class WhoisEnricher(BaseScanner):
    """
    Query WHOIS/ASN information for sub-asset IPs using a public API.
    """
    
    async def run(self, context: ScanContext) -> None:
        if not context.sub_assets:
            return
            
        logger.info(f"[WhoisEnricher] Starting enrichment for {len(context.sub_assets)} sub-assets.")
        
        # Extract unique IPs
        unique_ips = set()
        for sa in context.sub_assets:
            if "ips" in sa and sa["ips"]:
                for ip in sa["ips"]:
                    unique_ips.add(ip)
                    
        if not unique_ips:
            return
            
        whois_data = {}
        
        # We will use http://ip-api.com/json/IP
        # The free API is rate-limited to 45 requests per minute.
        
        async with aiohttp.ClientSession() as session:
            for ip in list(unique_ips):
                # Skip private/reserved addresses (handles IPv4 and IPv6)
                try:
                    if ipaddress.ip_address(ip).is_private:
                        continue
                except ValueError:
                    logger.debug(f"[WhoisEnricher] Invalid IP address, skipping: {ip}")
                    continue
                    
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query"
                try:
                    async with session.get(url, timeout=5) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("status") == "success":
                                whois_data[ip] = {
                                    "org": data.get("org", ""),
                                    "isp": data.get("isp", ""),
                                    "asn": data.get("as", ""),
                                    "location": f"{data.get('country', '')} {data.get('regionName', '')} {data.get('city', '')}".strip()
                                }
                            else:
                                logger.debug(f"IP API failed for {ip}: {data.get('message')}")
                        else:
                            logger.debug(f"IP API returned status {response.status} for {ip}")
                except Exception as e:
                    logger.debug(f"Error querying WHOIS for {ip}: {e}")
                
                # Sleep to respect rate limits (45 requests / 60s)
                await asyncio.sleep(1.5)
                
        if "whois_data" not in context.metadata:
            context.metadata["whois_data"] = {}
        context.metadata["whois_data"].update(whois_data)
        logger.info(f"[WhoisEnricher] Completed enrichment, gathered data for {len(whois_data)} IPs.")
