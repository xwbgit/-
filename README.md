# DAS-SentinelAgent 🛡️
### 自动化 Web 漏洞智能巡检、微内核插件解耦与系统架构拓扑推演平台

DAS-SentinelAgent (安恒星巡) 是一款集成了**全自动化 Web 资产爬取、多维漏洞主动探测、微内核插件化解耦、企业级架构拓扑动态推演与全流程非破坏性验证**的智能安全巡检平台。

---

## 🏛️ 项目架构与模块状态一览 (3 人团队并发解耦体系)

```text
📁 DAS_SentinelAgent/
├── 📁 frontend/                     -> 🎨 前端交互区 [状态: 运行正常] (Vue/React, CSS, HTML, Dashboard)
├── 📁 backend/                      -> ⚙️ 后端基座区 [状态: 运行正常] (FastAPI, 任务状态机, DB, Orchestrator 微内核)
├── 📁 plugins/                      -> 🛡️ 安全引擎插件区 [状态: 深度解耦接入核心]
│   ├── 📁 core/                     -> 插件通信基座 (Registry 递归发现器, ScanContext 数据总线, SRC-Filter)
│   ├── 📁 scanner_core/             -> 🎯 核心漏扫区 (VulnDetector, TamperDetector, SensitiveInspector)
│   └── 📁 scanner_extensions/       -> 🌐 漏扫扩展区 (按方向细分，与核心区无缝衔接)
│       ├── 📁 sub_assets/           -> ① 资产与子域名测绘方向 (爬虫/子域/架构指纹)
│       ├── 📁 exploit_chain/        -> ② 漏洞利用链与深度渗透方向 (利用链推演)
│       ├── 📁 link_processor/       -> ③ 特殊链接提取与外链清洗方向 (动态JS路由挖掘)
│       ├── 📁 api_fuzzer/           -> ④ REST API 接口轻量探测方向 (Swagger/API探针)
│       └── 📁 tool_adapters/       -> ⑤ 可选 Nuclei/Gitleaks/ZAP 真实命令行适配层
├── 📁 backend/app/evaluation/           -> 📊 标注集 Precision/Recall/F1/FPR 计算器
├── 📁 scripts/                      -> 🛠️ 辅助运维与调试脚本工具箱 (12个独立脚本集中收纳)
├── 📁 tests/                        -> 🧪 自动化测试套件（默认离线回归 + 可选本地靶场集成测试）
└── 📁 obsidian/                     -> 📖 Obsidian 双链体系完整知识库 (8篇全景笔记)
```

> [!TIP]
> **详细文档与 AI 交接清单请查看**：[`obsidian/00-🧭_项目总览与知识库导航.md`](obsidian/00-🧭_项目总览与知识库导航.md) 与 [`obsidian/07-🤖_AI协作与全局区域状态交接清单(AI_Handover).md`](obsidian/07-🤖_AI协作与全局区域状态交接清单(AI_Handover).md)。

---

## 🚀 本地极速启动与测试验证

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 运行默认离线回归测试（不访问外部站点）
python -m pytest -v

# 3. 显式运行本地靶场集成测试（PowerShell）
$env:RUN_LAB_INTEGRATION="1"
python -m pytest -v tests/test_agent_orchestrator.py tests/test_deep_vulnerabilities.py

# 4. 启动服务（真实目标模式，默认不启动内置测试靶场）
python run.py
```
- 控制台前端地址: `http://127.0.0.1:8000`

如需本地回归靶场，先设置 `ENABLE_BUILTIN_LAB=true` 后再运行 `python run.py`；靶场地址为 `http://127.0.0.1:8088`。该靶场只用于测试，不代表真实站点检测效果。

可选外部工具不随仓库捆绑，默认不执行。安装并审核对应工具后，可使用环境变量 `ENABLE_EXTERNAL_TOOLS=true` 和 `EXTERNAL_TOOL_ALLOWLIST=nuclei,gitleaks,zap` 开启。每次执行的版本、耗时、退出码和结果数会写入任务摘要 `tool_runs`。

CVE 关联不在巡检时联网；可将已下载的 NVD JSON 通过 `scripts/import_nvd_catalog.py` 转换为本地目录，并用 `CVE_CATALOG_PATH` 指定路径。缺少可复核版本或目录时，系统不会猜测 CVE。

---

## 🧩 核心与扩展无缝连接规范

扩展区域 (`scanner_extensions`) **绝不是独立孤岛**，它通过以下机制完全接入核心生命周期流水线：
1. **统一继承**：所有插件继承自 `plugins.core.base.BaseScanner` 并实现 `async def run(self, context: ScanContext)`；
2. **数据总线**：前置扩展（爬虫、子域、链接清洗）向 `ScanContext` 注入资产数据，核心区 (`scanner_core`) 读取资产并发起漏洞探测，后置扩展（利用链、API探针）读取漏洞并深化证明；
3. **零侵入自动装载**：`plugins/core/registry.py` 通过 `pkgutil.walk_packages` 深度递归遍历所有子包，新增任意方向插件无需修改后端调度代码即可全自动装载运行。
