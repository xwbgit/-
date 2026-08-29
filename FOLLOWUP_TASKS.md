# DAS-SentinelAgent 子资产漏扫扩展 — 后续开发任务书

> **交接说明**: 本文件由前序智能体 (Claude Opus 4.6) 编写，用于交接给 Gemini 3.1 Pro 继续开发。
> 前序工作已完成子资产漏扫的**大框架构建与核心模块**，以下 6 个任务是延伸开发项。
> 所有任务互相独立，可并行开发。

---

## 项目背景

DAS-SentinelAgent 是一个基于 Python (FastAPI) + 纯前端 (HTML/CSS/JS) 的网站安全巡检系统。
子资产扫描模块位于 `plugins/scanner_extensions/sub_assets/` 目录。

### 已完成的核心模块 (不需要重新开发)

| 文件 | 职责 |
|---|---|
| `sub_asset_expander.py` | 被动子域发现、crt.sh 证书透明度、DNS 解析、CNAME 接管检测 |
| `asset_crawler.py` | BFS 异步页面爬取、表单/JS/API 路由提取 |
| `fingerprint_detector.py` | Web Server/Frontend/Backend/DB 技术栈指纹识别 |
| `port_scanner.py` | **[新]** 异步 TCP Connect 扫描 (Top 100 端口) + Banner 抓取 + 服务识别 |
| `vuln_scanner.py` | **[新]** Redis/MongoDB/Docker/Actuator/FTP 等 7 类服务级漏洞探针 |
| `asset_correlator.py` | **[新]** IP 聚合、C 段关联、综合风险评分 |

### 架构约束

- **No NPM**: 前端使用纯 ES6 + CDN，禁止引入 Node.js 构建工具
- **BaseScanner 接口**: 所有扫描器必须继承 `plugins/core/base.py` 中的 `BaseScanner`，实现 `async def run(self, context: ScanContext)`
- **ScanContext 数据管道**: 通过 `context.add_findings()` 注入发现，通过 `context.metadata` 传递中间数据
- **SRC 合规**: 所有探测必须遵循 `plugins/core/scope_manager.py` 的授权边界

---

## 任务 1: 子资产递归爬取联动 (P0 - 最高优先级)

**目标**: 让 `asset_crawler.py` 对 `SubAssetExpander` 发现的每个授权子域自动启动二级 BFS 爬取。

**具体要求**:
1. 在 `sub_asset_expander.py` 的 `expand_and_probe_all()` 完成后，对每个 `visited=True` 且 `ownership_confirmed=True` 的子资产调用 `AssetCrawler`
2. 二级爬取深度限制为 `max_depth=2`、`max_pages=15`（避免指数爆炸）
3. 将二级爬取结果合并回 `ScanContext.crawled_pages`（去重）
4. 新建或修改: `sub_asset_expander.py`

**测试用例**: Mock 两个子域的爬取结果，验证去重逻辑和深度限制。

---

## 任务 2: HTTPS 证书安全审计 (P1)

**目标**: 新建 `cert_auditor.py`，对子资产执行 TLS/SSL 安全检查。

**具体要求**:
1. 使用 Python `ssl` 模块连接目标，提取证书信息
2. 检测项:
   - 证书是否过期
   - 是否自签名
   - TLS 版本 (拒绝 SSLv3, TLS 1.0, TLS 1.1)
   - 弱密码套件 (RC4, DES, NULL)
   - 证书域名是否匹配
3. 输出统一 Finding 格式
4. 新建: `plugins/scanner_extensions/sub_assets/cert_auditor.py`

**参考**: `port_scanner.py` 中 `scan_port()` 的 `asyncio.open_connection` 用法。

---

## 任务 3: 子资产历史基线对比 (P1)

**目标**: 跨扫描周期追踪子域名新增/消失/端口变更，生成差异报告。

**具体要求**:
1. 在 `backend/app/baseline/` 下新建 `sub_asset_baseline.py`
2. 每次子资产扫描完成后，将结果快照存入 SQLite `sub_asset_snapshots` 表
3. 提供 `compare_sub_asset_snapshots(task_id_old, task_id_new)` 方法
4. 输出: 新增子域列表、消失子域列表、端口变更列表
5. 在 `backend/app/api/baselines.py` 添加 API 端点

**参考**: 现有 `baseline_service.py` 的 findings 快照比对逻辑。

---

## 任务 4: 子资产拓扑前端可视化 (P2)

**目标**: 在前端用 Canvas 渲染子资产关系图。

**具体要求**:
1. 新建 `frontend/static/js/modules/topology.js`
2. 使用原生 Canvas API（不引入 D3.js 等库，除非通过 CDN）
3. 渲染内容:
   - IP 聚合: 多个子域指向同一 IP 时用连线聚合
   - C 段分布: 同网段资产用颜色分组
   - 风险热力图: 节点大小/颜色反映 `risk_score`
4. 数据来源: `asset_correlator.py` 输出的 `ip_clusters` 和 `risk_profiles`
5. 在 `frontend/static/js/app.js` 的任务详情页中集成

**参考**: `app.js` 中现有的 `generateObservedTopology()` 函数 (约第 809 行)。

---

## 任务 5: WHOIS/ASN 情报集成 (P2)

**目标**: 丰富子资产归属信息。

**具体要求**:
1. 新建 `plugins/scanner_extensions/sub_assets/whois_enricher.py`
2. 对每个子资产的 IP 查询 WHOIS/ASN 信息
3. 信息包括: 注册人/组织、ASN 号码、地理位置、注册商
4. 使用公开 API (如 `ip-api.com` 或 `ipwhois.app`)，注意限速
5. 将结果注入 `context.metadata["whois_data"]`

---

## 任务 6: 子资产专项报告导出 (P2)

**目标**: 生成独立的子资产安全评估报告。

**具体要求**:
1. 在 `backend/app/baseline/report_service.py` 添加 `generate_sub_asset_report(task_id)` 方法
2. 报告内容:
   - 子资产发现汇总表
   - 端口暴露统计
   - 高危服务列表
   - IP 聚合分析结果
   - 风险评分排名
3. 输出格式: Markdown
4. 在 `backend/app/api/reports.py` 添加端点 `GET /reports/{task_id}/sub-assets`

---

## 运行测试

```powershell
$env:PYTHONPATH="d:\Gemini Work\DAS_SentinelAgent"; pytest tests --basetemp=.pytest_temp -v
```

当前状态: **60 passed, 0 failed, 2 skipped**

每完成一个任务后，请运行全量测试确保无回退。
