import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseSettings):
    APP_NAME: str = "DAS-SentinelAgent (安恒星巡 - 网站安全智能巡检与敏感信息防泄露智能体)"
    APP_VERSION: str = "1.1.0"
    API_V1_STR: str = "/api/v1"
    
    # 存储与数据库
    DATABASE_PATH: str = str(DATA_DIR / "das_sentinel.db")
    REPORTS_DIR: str = str(DATA_DIR / "reports")
    SNAPSHOTS_DIR: str = str(DATA_DIR / "snapshots")
    
    DEFAULT_CONCURRENCY: int = 50
    DEFAULT_RATE_LIMIT_QPS: float = 50.0
    DEFAULT_TIMEOUT_SEC: float = 10.0
    DEFAULT_MAX_PAGES: int = 5000
    DEFAULT_MAX_DEPTH: int = 5
    DEFAULT_USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (DAS-SentinelAgent/1.0; Security Audit)"
    
    # 恒脑安全智能体对接配置
    HENGNAO_PLATFORM_URL: str = "https://gc.das-ai.com"
    HENGNAO_AGENT_ID: str = "agent-das-websec-inspector"
    HENGNAO_API_KEY: str = os.getenv("HENGNAO_API_KEY", "hengnao-sec-key-demo")
    
    # 告警配置
    DEFAULT_WEBHOOK_URL: str = ""
    ALERT_SEVERITY_THRESHOLD: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # 靶场与测试端口
    SERVER_HOST: str = "127.0.0.1"
    SERVER_PORT: int = 8000
    LAB_PORT: int = 8088

    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()

Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
Path(settings.SNAPSHOTS_DIR).mkdir(parents=True, exist_ok=True)
