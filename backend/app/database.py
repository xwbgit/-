import sqlite3
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from backend.app.config import settings

logger = logging.getLogger("das_sentinel.db")

def get_db_connection():
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. 巡检任务表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        target_url TEXT NOT NULL,
        auth_domains TEXT NOT NULL,          -- JSON Array 授权域名白名单
        scan_scope TEXT NOT NULL,            -- JSON: max_depth, max_pages, qps_limit
        cron_expr TEXT DEFAULT '',           -- 定时巡检 cron 表达式，空表示单次
        status TEXT DEFAULT 'PENDING',       -- PENDING, RUNNING, COMPLETED, FAILED, SCHEDULED
        progress INTEGER DEFAULT 0,          -- 0 - 100
        current_stage TEXT DEFAULT '',       -- 当前阶段描述
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        summary TEXT,                        -- JSON: 统计结果 (漏洞数、高危、中危等)
        parent_task_id TEXT,                 -- 周期模板或上一次执行的任务 ID
        run_kind TEXT DEFAULT 'MANUAL'       -- MANUAL, SCHEDULED_RUN, RETEST
    )
    """)

    # 兼容旧数据库：CREATE TABLE IF NOT EXISTS 不会自动增加新列。
    existing_task_columns = {row[1] for row in cursor.execute("PRAGMA table_info(tasks)").fetchall()}
    if "parent_task_id" not in existing_task_columns:
        cursor.execute("ALTER TABLE tasks ADD COLUMN parent_task_id TEXT")
    if "run_kind" not in existing_task_columns:
        cursor.execute("ALTER TABLE tasks ADD COLUMN run_kind TEXT DEFAULT 'MANUAL'")
    
    # 2. 漏洞/风险发现记录表 (Findings)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        category TEXT NOT NULL,              -- VULN (漏洞/弱配置), SENSITIVE (敏感信息), TAMPER (篡改/挂马), ASSET (资产风险)
        title TEXT NOT NULL,
        severity TEXT NOT NULL,              -- CRITICAL, HIGH, MEDIUM, LOW, INFO
        url TEXT NOT NULL,
        param TEXT DEFAULT '',
        evidence TEXT NOT NULL,              -- JSON: 请求报文/响应报文/上下文匹配高亮
        impact TEXT NOT NULL,                -- 危害影响分析
        remediation TEXT NOT NULL,           -- 修复建议
        verified INTEGER DEFAULT 0,          -- 是否经真实证据验证 (1: 是, 0: 疑似)
        cvss_score REAL DEFAULT 0.0,
        status TEXT DEFAULT 'OPEN',          -- OPEN, FIXED, IGNORED, FALSE_POSITIVE
        src_type TEXT DEFAULT 'BASELINE_HYGIENE', -- SRC_EXPLOITABLE (实战漏洞) vs BASELINE_HYGIENE (基线合规)
        created_at TEXT NOT NULL,
        verified_at TEXT,
        FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
    )
    """)
    
    # 3. 页面与资产基线快照表 (Baselines)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baselines (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        task_id TEXT NOT NULL,
        snapshot_time TEXT NOT NULL,
        pages_count INTEGER DEFAULT 0,
        assets_json TEXT NOT NULL,           -- 页面与静态资源指纹集合
        dom_hashes_json TEXT NOT NULL,       -- 关键页面 DOM Hash / SimHash
        findings_hash TEXT NOT NULL          -- 漏洞集合哈希，用于基线对比
    )
    """)
    
    # 4. 敏感信息自定义规则库 (Sensitive Rules)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sensitive_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,              -- ID_CARD, PHONE, BANK_CARD, SECRET_KEY, CUSTOM_REGEX, KEYWORD, FILE_TYPE
        pattern TEXT NOT NULL,               -- 正则表达式、关键词或后缀列表
        sample_data TEXT DEFAULT '',         -- 示例数据
        risk_level TEXT NOT NULL,            -- CRITICAL, HIGH, MEDIUM, LOW
        description TEXT DEFAULT '',
        is_builtin INTEGER DEFAULT 0,        -- 1: 内置规则, 0: 用户自定义
        enabled INTEGER DEFAULT 1,
        created_at TEXT NOT NULL
    )
    """)
    
    # 5. 安全审计日志表 (Audit Logs - 合规性要求)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,                -- TASK_START, RECON_PAGE, VULN_PROBE, TOOL_EXECUTE, ALERT_SENT
        operator TEXT DEFAULT 'SYSTEM_AGENT',
        target TEXT NOT NULL,
        details TEXT,
        status TEXT DEFAULT 'SUCCESS'
    )
    """)
    
    # 6. 智能体会话与推理记录表 (Agent Sessions)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_sessions (
        id TEXT PRIMARY KEY,
        task_id TEXT,
        user_prompt TEXT NOT NULL,
        plan_steps TEXT,                     -- JSON: 规划步骤列表
        execution_trace TEXT,                -- JSON: 思考过程、工具调用链与反思
        final_response TEXT,
        created_at TEXT NOT NULL
    )
    """)
    
    # 7. 子资产快照表 (Sub-Asset Snapshots) - 任务3新增
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sub_asset_snapshots (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        task_id TEXT NOT NULL,
        snapshot_time TEXT NOT NULL,
        sub_assets_count INTEGER DEFAULT 0,
        sub_assets_json TEXT NOT NULL,       -- JSON: 子资产列表
        port_results_json TEXT NOT NULL      -- JSON: 端口扫描结果
    )
    """)
    
    conn.commit()
    
    # 插入默认内置敏感信息规则
    insert_default_sensitive_rules(cursor)
    conn.commit()
    conn.close()
    logger.info("Database schema initialized successfully.")

def insert_default_sensitive_rules(cursor):
    cursor.execute("SELECT COUNT(*) FROM sensitive_rules WHERE is_builtin = 1")
    count = cursor.fetchone()[0]
    if count > 0:
        return
        
    builtin_rules = [
        ("rule-idcard", "中华人民共和国居民身份证", "ID_CARD", r"(?<![a-zA-Z0-9])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![a-zA-Z0-9])", "110101199003072345", "HIGH", "识别18位中国居民身份证号码", 1, 1),
        ("rule-phone", "中国大陆手机号码", "PHONE", r"(?<![a-zA-Z0-9])(?:(?:\+?86)?1(?:3\d|4[5-9]|5[0-35-9]|6[2567]|7[0-8]|8\d|9[0-35-9])\d{8})(?![a-zA-Z0-9])", "13800138000", "MEDIUM", "识别11位中国大陆手机号码", 1, 1),
        ("rule-bankcard", "银行卡/信用卡号", "BANK_CARD", r"(?<![a-zA-Z0-9_-])(?:62\d{14,17}|4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})(?![a-zA-Z0-9_-])", "6222021234567890123", "HIGH", "识别13至19位符合国际与银联BIN规范的银行卡卡号", 1, 1),

        ("rule-email", "电子邮箱地址", "KEYWORD", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "admin@example.gov.cn", "LOW", "识别暴露的个人与企业电子邮箱", 1, 1),
        ("rule-aksk-aliyun", "阿里云 AccessKey / SecretKey", "SECRET_KEY", r"(?<![a-zA-Z0-9+/=])LTAI[a-zA-Z0-9]{16,24}(?![a-zA-Z0-9+/=])", "LTAI4G1234567890abcdef", "CRITICAL", "阿里云 API 访问秘钥泄漏", 1, 1),
        ("rule-aksk-tencent", "腾讯云 SecretId / SecretKey", "SECRET_KEY", r"(?<![a-zA-Z0-9+/=])AKID[a-zA-Z0-9]{32}(?![a-zA-Z0-9+/=])", "AKIDz8kx6Ezabcd1234567890", "CRITICAL", "腾讯云 API 访问秘钥泄漏", 1, 1),

        ("rule-jwt", "JSON Web Token (JWT)", "SECRET_KEY", r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "eyJhbGciOi...", "MEDIUM", "客户端泄露的长期有效 JWT Token", 1, 1),
        ("rule-db-uri", "数据库连接串 (MySQL/PostgreSQL/Redis/Mongo)", "SECRET_KEY", r"(?:mysql|postgres|postgresql|redis|mongodb|sqlserver):\/\/[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.~!@#$%^&*()+-]+@[a-zA-Z0-9_.-]+:\d+", "mysql://root:pass@127.0.0.1:3306/db", "CRITICAL", "代码中硬编码的数据库连接串与账号密码", 1, 1),
        ("rule-backup-files", "敏感备份与源码泄露文件", "FILE_TYPE", r"\.(?:bak|sql|tar\.gz|zip|rar|7z|swp|env|git|svn|DS_Store|conf|config|yml|yaml|backup)(?=[?#\s]|$)", ".env, .git, backup.sql", "HIGH", "可能导致整站源码或数据库泄露的备份文件", 1, 1)
    ]
    now = datetime.now().isoformat()
    for rule in builtin_rules:
        cursor.execute("""
        INSERT INTO sensitive_rules (id, name, category, pattern, sample_data, risk_level, description, is_builtin, enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (*rule, now))
