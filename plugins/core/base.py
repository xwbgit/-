import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("das_sentinel.scanner_core")

@dataclass
class ScanContext:
    task_id: str
    target_url: str
    auth_domains: List[str] = field(default_factory=list)
    scan_scope: Dict[str, Any] = field(default_factory=dict)
    
    crawled_pages: List[Dict[str, Any]] = field(default_factory=list)
    js_scripts: List[Dict[str, Any]] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    static_assets: set = field(default_factory=set)
    api_endpoints: set = field(default_factory=set)
    
    sub_assets: List[Dict[str, Any]] = field(default_factory=list)
    topology_cluster: Dict[str, Any] = field(default_factory=dict)
    
    url_parameters: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_findings(self, new_findings: List[Dict[str, Any]]):
        self.findings.extend(new_findings)

class BaseScanner:
    @property
    def name(self) -> str:
        return self.__class__.__name__

    async def run(self, context: ScanContext) -> None:
        raise NotImplementedError("Scanner must implement the run() method.")
