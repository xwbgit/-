# DAS-SentinelAgent 开源工具与探针编排清单

本系统遵循**“轻量高效、安全合规、非破坏性”**原则，自主研发并编排了一系列合规开源工具与探针矩阵，确保对目标站点的所有检查均为只读探测，严格避免服务过载或数据破坏。

---

## 1. 编排工具与探针矩阵清单

| 模块类别 | 工具 / 探针名称 | 协议与来源 | 功能说明与检测项 | 非破坏性保障措施 |
| :--- | :--- | :--- | :--- | :--- |
| **资产与页面发现** | `AsyncAssetCrawler` | 自主研发 / 基于 `aiohttp` & `BeautifulSoup4` | 站点 URL 树递归发现、静态资源提取、JS 接口提取、外链与内链分类 | 严格限定域名边界，支持 QPS 限速与最大深度控制 |
| **漏洞与弱配置检测** | `SecurityHeadersProbe` | 开源最佳实践 (OWASP Secure Headers) | 检测 HSTS、CSP、X-Frame-Options、X-Content-Type-Options 缺失 | 仅读取 HTTP 响应头，无额外载荷 |
| **漏洞与弱配置检测** | `CORSMisconfigDetector` | 启发式探测模型 | 检测 `Access-Control-Allow-Origin: *` 与动态反射携密跨域缺陷 | 发送安全模拟 Origin 头，无注入破坏 |
| **漏洞与弱配置检测** | `SensitivePathScanner` | 灵感源自 `dirsearch` / `SecLists` | 针对 `.git/HEAD`、`.env`、`backup.sql`、`swagger-ui`、`actuator` 精准探测 | 仅发送 GET/HEAD 请求，匹配特征签名后立即截断 |
| **防篡改与反挂马** | `HiddenLinkDetector` | DOM 树解析引擎 | 识别 `display:none`、`visibility:hidden`、负坐标偏离等隐蔽暗链 | 离线解析 DOM 树，零网络额外请求 |
| **防篡改与反挂马** | `MaliciousScriptDetector` | 正则与语义签名引擎 | 识别 `coinhive` 挖矿脚本、混淆 `eval(unescape(...))`、恶意跳转 | 离线静态扫描 JS 脚本内容 |
| **防篡改与反挂马** | `DefacementIdentifier` | 关键词与语义比对 | 识别“Hacked by”黑客涂鸦标语、非法博彩及涉政涉黄违禁内容 | 纯文本与 DOM 语义离线分析 |
| **敏感信息防泄露** | `ChecksumSensitiveInspector` | 自主研发 (集成 ISO/Luhn 算法) | 识别中国大陆 18 位身份证 (校验位)、11 位手机号、银行卡 (Luhn)、企业 AK/SK | 内存算法校验，自动脱敏输出掩码 |
| **敏感信息防泄露** | `CustomEnterpriseRuleEngine`| 自定义规则引擎 | 支持单位自定义关键词、正则表达式、敏感文件后缀实时匹配与沙箱测试 | 纯内存沙箱执行，安全可控 |
| **基线与持续运营** | `BaselineDiffEngine` | 基于 SHA-256 / SimHash | 历史快照版本比对、DOM 异动告警、漏洞闭环状态追踪 | 数据库内离线比对 |
| **定时调度** | `APScheduler` | 开源 `APScheduler 3.10+` | 周期性巡检任务调度 (支持 Cron 表达式) | 异步轻量调度器 |
| **可选外部漏扫** | `NucleiAdapter` | ProjectDiscovery Nuclei | 检查可执行文件和版本，运行签名模板并解析 JSONL | 授权域校验、QPS/超时、禁用未签名模板，排除 dos/fuzz/intrusive/bruteforce 标签 |
| **可选外部敏感检查** | `GitleaksAdapter` | Gitleaks | 将已爬取 HTML/JS 写入临时目录后扫描，转换 JSON 报告 | 不克隆目标仓库，报告强制 `--redact=100`，不持久化密钥原文 |
| **可选外部配置检查** | `ZapBaselineAdapter` | OWASP ZAP Baseline | 运行限时蜘蛛和被动扫描，解析 JSON 报告 | 仅接入 Baseline，不调用 Full Scan/主动攻击扫描 |

---

## 2. 安全合规与非破坏性设计承诺

1. **严格授权边界**：爬虫与探测探针在发起请求前，必须通过 `is_authorized()` 域名白名单匹配，严禁越界探测未经授权的外部网络。
2. **非破坏性验证**：不发送含有 SQL 注入破坏性删表、XSS 弹窗利用、命令执行溢出等可能导致目标业务中断或数据污染的 Payload。
3. **速率控制 (Rate Limiting)**：默认 QPS 限制为 5.0，并发上限为 20，同时设置请求和外部工具超时。
4. **全流程审计日志**：每一次探针调用、资产发现、漏洞触发均记录于系统 `audit_logs` 表中，满足等保与日志留存合规要求。

## 3. 外部工具开启方式

外部工具默认关闭，且不随项目镜像捆绑分发。部署者应先独立审核、安装所需二进制，再设置：

```dotenv
ENABLE_EXTERNAL_TOOLS=true
EXTERNAL_TOOL_ALLOWLIST=nuclei,gitleaks,zap
EXTERNAL_TOOL_TIMEOUT_SEC=180
```

未安装、未在允许清单、超时或返回异常的工具会在任务摘要 `tool_runs` 中记录 `SKIPPED`/`TIMED_OUT`/`FAILED`，不会生成虚假 Finding。

## 4. 指纹与 CVE 关联

指纹引擎只在响应头、HTML 特征或已保存发现证据中出现明确产品和版本时生成 CPE 候选。`CVEIntelMatcher` 仅读取本地 `CVE_CATALOG_PATH`，根据受影响版本边界关联；命中结果统一标为“版本关联待复核”，不作为已验证漏洞。

可使用已下载的 NVD CVE API 2.0 JSON 生成本地目录：

```powershell
python scripts/import_nvd_catalog.py nvd-export.json data/cve_catalog.json --source-label "NVD CVE API 2.0 export 2026-08-28"
```

如目录不存在或格式错误，报告中只记录 `NOT_CONFIGURED`/`INVALID_CATALOG`，不会生成 CVE Finding。
