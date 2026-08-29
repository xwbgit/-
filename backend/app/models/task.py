from pydantic import BaseModel, Field, model_validator
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from backend.app.config import settings

class TaskCreateRequest(BaseModel):
    name: str = Field(..., description="巡检任务名称")
    target_url: str = Field(..., description="目标站点根 URL")
    auth_domains: List[str] = Field(default_factory=list, description="授权域名清单，如 ['example.com', 'sub.example.com']")
    max_depth: int = Field(default=settings.DEFAULT_MAX_DEPTH, ge=1, le=5, description="爬取最大深度")
    max_pages: int = Field(default=settings.DEFAULT_MAX_PAGES, ge=5, le=500, description="最大发现页面数")
    qps_limit: float = Field(default=settings.DEFAULT_RATE_LIMIT_QPS, ge=0.5, le=20.0, description="请求并发速率限制")
    cron_expr: Optional[str] = Field(default="", description="定时 Cron 表达式，例如 '0 2 * * *' (每天凌晨2点)")
    enable_tamper_check: bool = Field(default=True, description="是否启用暗链与挂马篡改检测")
    enable_sensitive_check: bool = Field(default=True, description="是否启用敏感信息检测")
    enable_vuln_check: bool = Field(default=True, description="是否启用常见漏洞与配置缺陷检测")
    custom_sensitive_keywords: List[str] = Field(default_factory=list, description="临时追加的本单位特定敏感关键词")

    @model_validator(mode="after")
    def validate_authorized_target(self):
        parsed = urlparse(self.target_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("target_url 必须是有效的 http/https URL")
        if parsed.username or parsed.password:
            raise ValueError("target_url 不得携带明文用户名或密码")
        if not self.auth_domains:
            raise ValueError("必须明确填写并确认至少一个授权域名")

        target_host = parsed.hostname.lower()
        normalized_domains = [domain.strip().lower().lstrip("*.") for domain in self.auth_domains if domain.strip()]
        if not any(target_host == domain or target_host.endswith("." + domain) for domain in normalized_domains):
            raise ValueError("目标站点不在已确认的授权域名范围内")
        self.auth_domains = normalized_domains
        return self

class TaskResponse(BaseModel):
    id: str
    name: str
    target_url: str
    auth_domains: List[str]
    status: str
    progress: int
    current_stage: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    summary: Optional[Dict[str, Any]]
