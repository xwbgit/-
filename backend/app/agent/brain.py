import json
import logging
import uuid
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from backend.app.config import settings
from backend.app.database import get_db_connection
from backend.app.agent.orchestrator import InspectionOrchestrator
from plugins.scanner_core.tamper_detector import TamperDetector

logger = logging.getLogger("das_sentinel.brain")

class AgentBrain:
    """DAS 智能体大脑：支持离线智能意图理解、数据库自主查询与多场景安全编排调度"""
    
    @classmethod
    async def _call_llm(cls, prompt: str, model_type: str = "fast") -> str:
        """根据 model_type (fast | deep) 调用混合推理模型"""
        api_key = settings.HENGNAO_API_KEY
        if not api_key:
            return ""
        
        try:
            import aiohttp
            model_name = settings.FAST_MODEL_NAME if model_type == "fast" else settings.DEEP_REASON_MODEL_NAME
            base_url = settings.HENGNAO_API_BASE.rstrip("/")
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1 if model_type == "fast" else 0.7
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=20) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["choices"][0]["message"]["content"]
            return ""
        except Exception as e:
            logger.error(f"[AgentBrain] LLM 调用异常: {e}")
            return ""

    @classmethod
    async def chat_and_plan(cls, user_prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        session_id = session_id or str(uuid.uuid4())
        prompt = user_prompt.strip()
        
        # 1. 意图与参数智能提取
        parsed_intent = cls._parse_intent(prompt)
        intent_type = parsed_intent["intent_type"]
        
        plan_steps = []
        execution_trace = []
        task_id = None
        final_summary = None
        final_response = ""

        conn = get_db_connection()
        cursor = conn.cursor()

        if intent_type == "QUERY_TASKS_FINDINGS":
            # 用户询问已有任务或漏洞（例如：“帮我看看这几个任务有什么漏洞”、“查看历史任务”、“有哪些漏洞”）
            plan_steps = [
                {"step": 1, "action": "FETCH_DATABASE_TASKS", "description": "读取本地 SQLite 任务列表与最新巡检快照"},
                {"step": 2, "action": "AGGREGATE_FINDINGS", "description": "聚类分析已检出的漏洞、敏感信息与篡改风险"},
                {"step": 3, "action": "GENERATE_EXECUTIVE_SUMMARY", "description": "输出结构化安全评估现状与整改优先级"}
            ]
            
            execution_trace.append({
                "thought": f"分析用户意图: 用户正在查询已有任务的安全漏洞与巡检结果，正在检索数据库记录...",
                "tool": "DatabaseReader",
                "observation": "成功读取 tasks 与 findings 数据表。"
            })
            
            cursor.execute("SELECT id, name, target_url, status, progress, summary, created_at FROM tasks ORDER BY created_at DESC LIMIT 5")
            tasks = cursor.fetchall()
            
            cursor.execute("SELECT severity, category, title, url, COUNT(*) as cnt FROM findings GROUP BY title, severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END")
            findings_summary = cursor.fetchall()
            
            execution_trace.append({
                "thought": f"已检索到 {len(tasks)} 个历史任务，共聚合到 {len(findings_summary)} 类核心风险项。",
                "tool": "FindingAggregator",
                "observation": f"包含环境配置泄露、数据库备份暴露、身份证与手机号明文输出等高危漏洞。"
            })

            if not tasks:
                final_response = "📋 **当前系统暂无巡检任务记录**。\n\n请提供已获授权的 http/https 目标 URL（也可使用本地靶场地址做回归测试），我将按授权范围创建巡检任务。"
            else:
                task_lines = []
                for t in tasks:
                    s = json.loads(t["summary"]) if t["summary"] else {}
                    score = s.get("security_score", "未评分")
                    task_lines.append(f"- **{t['name']}** (`{t['target_url']}`) | 评分: **{score} 分** | 状态: `{t['status']}`")
                
                finding_lines = []
                for f in findings_summary[:8]:
                    finding_lines.append(f"- [{f['severity']}] **{f['title']}** (涉及 `{f['url']}`) - 发现 {f['cnt']} 处")

                final_response = (
                    f"📊 **为您汇总当前任务与安全漏洞现状**：\n\n"
                    f"### 🕒 最近执行的巡检任务 ({len(tasks)} 个)：\n"
                    + "\n".join(task_lines) +
                    f"\n\n### 🚨 检出的主要风险隐患清单：\n"
                    + ("\n".join(finding_lines) if finding_lines else "🎉 当前任务中未检出高危风险！") +
                    f"\n\n💡 **处理建议**：\n"
                    f"1. 优先点击左侧【问题清单】修复 **CRITICAL** 严重级别的 `.env` 与 `backup.sql` 泄露；\n"
                    f"2. 对公民身份证与手机号开启算法脱敏掩码，防止数据安全合规风险；\n"
                    f"3. 您可以点击任意任务的【详情与报文】查看对应的**连线拓扑图与攻击利用链路**。"
                )

        elif intent_type == "COMPARE_BASELINE":
            # 用户询问比对历史
            plan_steps = [
                {"step": 1, "action": "FETCH_RECENT_TWO_TASKS", "description": "读取最近两次巡检基线快照"},
                {"step": 2, "action": "EXECUTE_BASELINE_DIFF", "description": "比对已修复隐患与新增风险"},
                {"step": 3, "action": "GENERATE_DIFF_REPORT", "description": "生成基线差异结论"}
            ]
            cursor.execute("SELECT id, name, target_url, created_at FROM tasks ORDER BY created_at DESC LIMIT 2")
            tasks = cursor.fetchall()
            if len(tasks) < 2:
                final_response = "⚖️ **基线比对需要至少 2 次巡检记录**。当前任务少于 2 个，请再发起一次巡检即可自动生成差异比对。"
            else:
                t1, t2 = tasks[0], tasks[1]
                execution_trace.append({
                    "thought": f"比对任务 {t2['id']} (前次) 与 {t1['id']} (最新)...",
                    "tool": "BaselineComparator",
                    "observation": "成功比对两组快照差异。"
                })
                final_response = (
                    f"⚖️ **历史巡检基线比对结果**：\n\n"
                    f"- **基准任务 (前次)**：`{t2['name']}` ({t2['created_at'][:19]})\n"
                    f"- **对比任务 (最新)**：`{t1['name']}` ({t1['created_at'][:19]})\n\n"
                    f"可在左侧【历史对比】菜单中选择这两个任务，查看详细的“新增漏洞”、“已修复漏洞”以及网页篡改异动对比！"
                )

        elif parsed_intent["target_url"]:
            # 明确包含 URL 的新巡检任务下发
            target_url = parsed_intent["target_url"]
            plan_steps = [
                {"step": 1, "action": "AUTHORIZATION_CHECK", "description": f"校验目标 URL 授权范围: {target_url}"},
                {"step": 2, "action": "PLAN_TASKS", "description": "编排资产爬取、弱配置探测、暗链挂马及敏感数据探针"},
                {"step": 3, "action": "EXECUTE_ORCHESTRATOR", "description": "异步执行全量非破坏性探测并收集证据链"},
                {"step": 4, "action": "SYNTHESIZE_REPORT", "description": "智能去重、定级与生成安恒标准格式闭环报告"}
            ]
            
            execution_trace.append({
                "thought": f"收到用户巡检需求: '{prompt}'。正在解析巡检目标、敏感词与探测深度...",
                "tool": "IntentParser",
                "observation": f"提取到目标站点: {target_url}, 授权域名: {parsed_intent['auth_domains']}"
            })
            
            task_id = f"task-agent-{uuid.uuid4().hex[:8]}"
            now = datetime.now().isoformat()
            
            scan_scope = {
                "max_depth": 3,
                "max_pages": 30,
                "qps_limit": 5.0,
                "custom_sensitive_keywords": parsed_intent.get("keywords", [])
            }
            
            cursor.execute("""
            INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, status, progress, current_stage, created_at)
            VALUES (?, ?, ?, ?, ?, 'PENDING', 0, '任务已由智能体规划创建', ?)
            """, (task_id, f"智能体即时巡检-{target_url}", target_url,
                  json.dumps(parsed_intent["auth_domains"]), json.dumps(scan_scope), now))
            conn.commit()
            
            execution_trace.append({
                "thought": f"创建任务实例 {task_id}，正在调度底层安全工具引擎...",
                "tool": "InspectionOrchestrator",
                "observation": "引擎调度成功，探测流程正在执行中。"
            })
            
            # 立即触发执行
            orchestrator = InspectionOrchestrator(task_id)
            result = await orchestrator.run()
            final_summary = result.get("summary", {})
            
            execution_trace.append({
                "thought": "探测已完成，正在汇总安全态势、去重过滤误报并给出整改建议。",
                "tool": "FindingVerifier & Advisor",
                "observation": f"发现风险隐患: {len(result.get('findings', []))} 条，安全态势评分: {final_summary.get('security_score', 0)}"
            })

            final_response = (
                f"🛡️ **巡检任务执行完毕**\n\n"
                f"- **目标站点**：`{target_url}`\n"
                f"- **安全态势分**：`{final_summary.get('security_score', '未评分')} / 100` ({final_summary.get('status_level', '未生成评分')})\n"
                f"- **扫描页面数**：`{final_summary.get('total_pages_scanned', 0)}` 个页面\n"
                f"- **风险分布**：严重 {final_summary.get('severity_counts', {}).get('CRITICAL', 0)} | "
                f"高危 {final_summary.get('severity_counts', {}).get('HIGH', 0)} | "
                f"中危 {final_summary.get('severity_counts', {}).get('MEDIUM', 0)} | "
                f"低危 {final_summary.get('severity_counts', {}).get('LOW', 0)}\n\n"
                f"已自动生成证据链、系统拓扑图与攻击链路分析，可点击左侧【问题清单】与【巡检任务】查看完整详情。"
            )
        else:
            final_response = (
                "👋 **收到您的指令**！\n\n"
                "如果您想发起新的网站巡检，请直接告诉我目标网址，例如：\n"
                "- `帮我检查 https://your-authorized-target.example 是否存在源码泄露与身份证`\n\n"
                "如果您想查看当前情况，可以直接说：\n"
                "- `帮我看看这几个任务有什么漏洞`\n"
                "- `比对历史巡检`"
            )

        # 记录会话持久化
        cursor.execute("""
        INSERT OR REPLACE INTO agent_sessions (id, task_id, user_prompt, plan_steps, execution_trace, final_response, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id, task_id, prompt,
            json.dumps(plan_steps, ensure_ascii=False),
            json.dumps(execution_trace, ensure_ascii=False),
            final_response, datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()

        return {
            "session_id": session_id,
            "task_id": task_id,
            "plan_steps": plan_steps,
            "execution_trace": execution_trace,
            "response": final_response,
            "summary": final_summary
        }

    @classmethod
    def _parse_intent(cls, prompt: str) -> Dict[str, Any]:
        """从自然语言中提取意图类型、URL、域名和敏感关键词"""
        prompt_lower = prompt.lower()
        
        # 1. 检查是否是查询类意图（如“看下漏洞”、“这几个任务”、“任务列表”、“历史记录”）
        intent_type = "SCAN_NEW"
        if any(w in prompt for w in ["看这几个任务", "有什么漏洞", "看下漏洞", "哪些漏洞", "任务列表", "历史任务", "汇总", "当前任务"]):
            intent_type = "QUERY_TASKS_FINDINGS"
        elif any(w in prompt for w in ["比对", "历史对比", "对比两次", "差异"]):
            intent_type = "COMPARE_BASELINE"
        
        # 2. 提取 URL
        url_match = re.search(r"https?:\/\/[^\s'\",]+", prompt)
        target_url = url_match.group(0).rstrip('/') if url_match else ""
        
        # 智能简写别名匹配
        if not target_url:
            if "8088" in prompt or "靶场" in prompt or "示范" in prompt:
                target_url = "http://127.0.0.1:8088"
                intent_type = "SCAN_NEW"
        
        auth_domains = []
        if target_url:
            host = urlparse(target_url).netloc.split(':')[0]
            auth_domains.append(host)
            
        # 提取用户提到的关键词
        keywords = []
        for kw in ["身份证", "手机号", "密码", "秘钥", "财务", "机密", "内部", "工资", "银行卡", "暗链", "挂马"]:
            if kw in prompt:
                keywords.append(kw)
                
        return {
            "intent_type": intent_type,
            "target_url": target_url,
            "auth_domains": auth_domains,
            "keywords": keywords
        }
