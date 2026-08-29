import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    APP_NAME: str = "DAS-SentinelAgent (安恒星巡 - 网站安全智能巡检与敏感信息防泄露智能体)"
    APP_VERSION: str = "1.1.0"
    API_V1_STR: str = "/api/v1"
    
    # 存储与数据库
    DATABASE_PATH: str = str(DATA_DIR / "das_sentinel.db")
    REPORTS_DIR: str = str(DATA_DIR / "reports")
    SNAPSHOTS_DIR: str = str(DATA_DIR / "snapshots")
    
    DEFAULT_CONCURRENCY: int = 20
    DEFAULT_RATE_LIMIT_QPS: float = 5.0
    DEFAULT_TIMEOUT_SEC: float = 10.0
    DEFAULT_MAX_PAGES: int = 100
    DEFAULT_MAX_DEPTH: int = 3
    DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (DAS-SentinelAgent/1.0; Security Audit)"
    CORS_ALLOW_ORIGINS: str = "http://127.0.0.1:8000,http://localhost:8000"

    # 可选外部开源工具：默认关闭，需部署者安装工具并显式开启。
    ENABLE_EXTERNAL_TOOLS: bool = False
    EXTERNAL_TOOL_ALLOWLIST: str = "nuclei,gitleaks,zap"
    EXTERNAL_TOOL_TIMEOUT_SEC: int = 180
    EXTERNAL_TOOL_MAX_OUTPUT_BYTES: int = 5 * 1024 * 1024
    CVE_CATALOG_PATH: str = str(DATA_DIR / "cve_catalog.json")
    
    # 恒脑安全智能体对接配置
    HENGNAO_PLATFORM_URL: str = "https://gc.das-ai.com"
    HENGNAO_AGENT_ID: str = "agent-das-websec-inspector"
    # 凭证只能由部署环境注入；仓库不提供可用的演示密钥。
    HENGNAO_API_KEY: str = os.getenv("HENGNAO_API_KEY", "")

    # MsgBox 开发者工作台为可选集成。未配置时不得自动请求第三方站点，
    # 也不得在接口响应或前端代码中暴露任何内置 Token。
    MSGBOX_TARGET_URL: str = ""
    MSGBOX_API_TOKEN: str = ""
    
    # 告警配置
    DEFAULT_WEBHOOK_URL: str = ""
    ALERT_SEVERITY_THRESHOLD: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # 靶场与测试端口
    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8000
    ENABLE_BUILTIN_LAB: bool = False
    LAB_HOST: str = "127.0.0.1"
    LAB_PORT: int = 8088

settings = Settings()

Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.SNAPSHOTS_DIR).mkdir(parents=True, exist_ok=True)
