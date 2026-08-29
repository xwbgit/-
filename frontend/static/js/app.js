const API_BASE = '/api/v1';
const taskConfig = {
    max_depth: { default: 3, min: 1, max: 5 },
    max_pages: { default: 100, min: 5, max: 500 },
    qps_limit: { default: 5.0, min: 0.5, max: 20.0 }
};

let activeTab = 'dashboard';
let pollingTimer = null;
let heartbeatTimer = null;
let heartbeatOk = true;
let currentDetailTaskId = null;
let currentTaskDetailData = null;
let selectedFindingIndex = 0;
let selectedTopologyFindingIndex = 0;
let selectedTopologyNodeId = null;
let topologyCanvasHeight = 1200;
let currentHttpViewTab = 'request';
let currentBurpSubTab = 'sitemap';
let currentSitemapFilter = 'ALL';
let selectedLogItem = null;
let focusPageUrl = null;
let selectedUrlFilter = '';

// DOM 加载完成后立即渲染
document.addEventListener('DOMContentLoaded', () => {
    initNav();
    renderTabContent('dashboard');
    startPolling();
    startHeartbeat();
});

// ─── 30 秒心跳定时器 ─────────────────────────────────────────────────────────
function startHeartbeat() {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    // 立即执行一次
    checkHeartbeat();
    // 之后每 30 秒检测一次
    heartbeatTimer = setInterval(checkHeartbeat, 30000);
}

async function checkHeartbeat() {
    const indicator = document.getElementById('hb-indicator');
    const uptimeEl  = document.getElementById('hb-uptime');
    try {
        const res = await fetch(`${API_BASE}/heartbeat`, { signal: AbortSignal.timeout(5000) });
        if (res.ok) {
            const data = await res.json();
            heartbeatOk = true;
            if (indicator) {
                indicator.title = `后端服务正常 ✓ 运行时长 ${data.uptime}`;
                indicator.style.background = '#22c55e';
                indicator.style.boxShadow = '0 0 6px #22c55e';
            }
            if (uptimeEl) uptimeEl.innerText = data.uptime;
        } else {
            throw new Error(`HTTP ${res.status}`);
        }
    } catch (e) {
        heartbeatOk = false;
        if (indicator) {
            indicator.title = `后端心跳丢失！(${e.message})`;
            indicator.style.background = '#ef4444';
            indicator.style.boxShadow = '0 0 8px #ef4444';
        }
        if (uptimeEl) uptimeEl.innerText = '--:--:--';
        console.warn('[Heartbeat] Backend unreachable:', e.message);
    }
}
// ─────────────────────────────────────────────────────────────────────────────

function initNav() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            activeTab = item.dataset.tab;
            currentDetailTaskId = null;
            renderTabContent(activeTab);
        });
    });
}

function startPolling() {
    updateTokenTelemetry();
    if (pollingTimer) clearInterval(pollingTimer);
    pollingTimer = setInterval(() => {
        if (activeTab === 'dashboard' && !currentDetailTaskId) loadDashboardStats();
        if (activeTab === 'tasks' && !currentDetailTaskId) loadTasksTable();
        if (currentDetailTaskId) refreshTaskDetailsLive();
        updateTokenTelemetry();
    }, 5000);
}

async function updateTokenTelemetry() {
    try {
        const res = await fetch(`${API_BASE}/reports/token-stats`);
        if (res.ok) {
            const data = await res.json();
            const el = document.getElementById('topbar-token-count');
            if (el) {
                if (data.total_tokens) {
                    const m = (data.total_tokens / 1000000).toFixed(2);
                    el.innerText = `${m}M Tokens (约 ¥${data.estimated_cost_cny ?? '--'})`;
                } else {
                    el.innerText = '未配置统计';
                }
            }
        }
    } catch (e) {}
}

function renderTabContent(tab) {
    activeTab = tab;
    const titleElem = document.getElementById('tab-title');
    if (titleElem) titleElem.innerText = getTabTitle(tab);
    
    const container = document.getElementById('main-content');
    if (!container) return;
    
    if (tab === 'dashboard') {
        container.innerHTML = getDashboardHTML();
        loadDashboard();
    } else if (tab === 'agent') {
        container.innerHTML = getAgentHTML();
        initAgentEvents();
    } else if (tab === 'tasks') {
        container.innerHTML = getTasksHTML();
        loadTasksTable();
    } else if (tab === 'findings') {
        container.innerHTML = getFindingsHTML();
        loadFindingsTable();
    } else if (tab === 'baseline') {
        container.innerHTML = getBaselineHTML();
        loadBaselineOptions();
    } else if (tab === 'rules') {
        container.innerHTML = getRulesHTML();
        loadRulesTable();
    } else if (tab === 'hengnao') {
        container.innerHTML = getHengnaoHTML();
        loadHengnaoManifest();
    } else if (tab === 'audit') {
        container.innerHTML = getAuditHTML();
        loadAuditLogs();
    } else if (tab === 'msgbox_tool') {
        container.innerHTML = getMsgBoxToolHTML();
        initMsgBoxTool();
    }
}

function getTabTitle(tab) {
    const map = {
        dashboard: '安全总览与快速巡检',
        agent: '智能助手 (打字对话下发巡检)',
        tasks: '巡检任务管理与定时器',
        findings: '安全问题清单与复测',
        baseline: '历史巡检对比 (查看变化与修复情况)',
        rules: '敏感隐私规则库与在线沙箱测试',
        hengnao: '安恒恒脑安全平台对接',
        audit: '安全操作记录 (全程合规留痕)',
        msgbox_tool: 'MsgBox 开发者接口与专项测试工作台 (API Security Workbench)'
    };
    return map[tab] || '控制台';
}

/* ---------------- 1. DASHBOARD ---------------- */
function getDashboardHTML() {
    return `
    <div class="grid-4">
        <div class="card">
            <div class="card-title"><span>综合安全健康分</span> <span>🛡️</span></div>
            <div class="card-val" id="stat-score" style="color: #16a34a;">--</div>
            <div class="card-sub" id="stat-status-text">系统计算中...</div>
        </div>
        <div class="card">
            <div class="card-title"><span>危险漏洞 / 泄露</span> <span>🚨</span></div>
            <div class="card-val" id="stat-critical" style="color: #dc2626;">--</div>
            <div class="card-sub">高危与敏感隐私问题</div>
        </div>
        <div class="card">
            <div class="card-title"><span>累计巡检任务</span> <span>🚀</span></div>
            <div class="card-val" id="stat-tasks" style="color: #0284c7;">--</div>
            <div class="card-sub">包含即时与定时任务</div>
        </div>
        <div class="card">
            <div class="card-title"><span>敏感信息规则</span> <span>🔒</span></div>
            <div class="card-val" id="stat-rules" style="color: #4f46e5;">--</div>
            <div class="card-sub">内置与自定义隐私规则</div>
        </div>
    </div>

    <div class="grid-2">
        <div class="card">
            <div class="card-title"><span>🚀 一键快速启动网站巡检</span></div>
            <p style="font-size:13px; color:#64748b; margin-bottom:14px;">输入目标网址，智能体会自动寻找页面、探测源码漏洞、检查身份证/手机号泄露并排查暗链：</p>
            <div style="display:flex; gap:10px; margin-bottom:12px;">
                <input type="text" id="quick-target-url" class="form-input" placeholder="输入已获授权的网站网址" value="">
                <button class="btn btn-primary" onclick="triggerQuickScan()">开始检查</button>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <button class="btn" style="font-size:12px; padding:4px 10px;" onclick="document.getElementById('quick-target-url').value='http://127.0.0.1:8088'">🎯 填入内置示范靶场 (8088)</button>
            </div>
        </div>

        <div class="card">
            <div class="card-title"><span>📊 安全问题分类统计</span></div>
            <div id="risk-category-bars" style="margin-top:10px; display:flex; flex-direction:column; gap:12px;">
                <div>
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                        <span>源码与配置弱点 (如 .git, .env, backup)</span> <span id="bar-vuln-cnt" style="font-weight:bold;">0 项</span>
                    </div>
                    <div class="progress-bar"><div id="bar-vuln" class="progress-val" style="width:0%; background:#dc2626;"></div></div>
                </div>
                <div>
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                        <span>敏感数据泄露 (身份证、手机号、秘钥)</span> <span id="bar-sens-cnt" style="font-weight:bold;">0 项</span>
                    </div>
                    <div class="progress-bar"><div id="bar-sens" class="progress-val" style="width:0%; background:#ea580c;"></div></div>
                </div>
                <div>
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                        <span>页面篡改与隐藏暗链 (黑产跳转、挖矿)</span> <span id="bar-tamper-cnt" style="font-weight:bold;">0 项</span>
                    </div>
                    <div class="progress-bar"><div id="bar-tamper" class="progress-val" style="width:0%; background:#d97706;"></div></div>
                </div>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><span>🕒 最近巡检任务记录</span> <button class="btn" style="font-size:12px; padding:3px 8px;" onclick="renderTabContent('tasks')">查看全部任务</button></div>
        <div id="recent-tasks-container">正在加载数据...</div>
    </div>
    `;
}

async function loadDashboard() {
    await loadDashboardStats();
}

async function loadDashboardStats() {
    try {
        const [tasksRes, findingsRes, rulesRes] = await Promise.all([
            fetch(`${API_BASE}/tasks`),
            fetch(`${API_BASE}/findings`),
            fetch(`${API_BASE}/rules`)
        ]);
        const tasks = await tasksRes.json();
        const findings = await findingsRes.json();
        const rules = await rulesRes.json();

        const statTasks = document.getElementById('stat-tasks');
        const statCritical = document.getElementById('stat-critical');
        const statScore = document.getElementById('stat-score');
        const statRules = document.getElementById('stat-rules');
        const statStatusText = document.getElementById('stat-status-text');

        if (statTasks) statTasks.innerText = tasks.length;
        if (statRules) statRules.innerText = rules.length;
        
        const criticalHigh = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
        if (statCritical) statCritical.innerText = criticalHigh;

        if (tasks.length > 0 && tasks[0].summary) {
            const score = tasks[0].summary.security_score !== undefined ? tasks[0].summary.security_score : null;
            if (statScore) {
                statScore.innerText = score === null ? '--' : score;
                statScore.style.color = score === null ? '#64748b' : (score >= 85 ? '#16a34a' : (score >= 60 ? '#d97706' : '#dc2626'));
            }
            if (statStatusText) {
                statStatusText.innerText = score === null ? '⚪ 尚未生成评分' : (score >= 85 ? '🟢 安全状态良好' : (score >= 60 ? '🟡 存在安全隐患' : '🔴 面临严重风险'));
            }
        } else {
            if (statScore) {
                statScore.innerText = '--';
                statScore.style.color = '#64748b';
            }
            if (statStatusText) statStatusText.innerText = '⚪ 尚未生成评分';
        }

        const vulnCnt = findings.filter(f => f.category === 'VULN').length;
        const sensCnt = findings.filter(f => f.category === 'SENSITIVE').length;
        const tamperCnt = findings.filter(f => f.category === 'TAMPER').length;
        const total = Math.max(findings.length, 1);

        if (document.getElementById('bar-vuln-cnt')) document.getElementById('bar-vuln-cnt').innerText = `${vulnCnt} 项`;
        if (document.getElementById('bar-sens-cnt')) document.getElementById('bar-sens-cnt').innerText = `${sensCnt} 项`;
        if (document.getElementById('bar-tamper-cnt')) document.getElementById('bar-tamper-cnt').innerText = `${tamperCnt} 项`;

        if (document.getElementById('bar-vuln')) document.getElementById('bar-vuln').style.width = `${(vulnCnt/total)*100}%`;
        if (document.getElementById('bar-sens')) document.getElementById('bar-sens').style.width = `${(sensCnt/total)*100}%`;
        if (document.getElementById('bar-tamper')) document.getElementById('bar-tamper').style.width = `${(tamperCnt/total)*100}%`;

        const recentBox = document.getElementById('recent-tasks-container');
        if (recentBox) {
            if (tasks.length === 0) {
                recentBox.innerHTML = '<p style="color:#64748b; font-size:13px; padding:16px 0;">暂无巡检任务，点击上方即可发起。</p>';
            } else {
                let html = '<table class="data-table"><thead><tr><th>任务名称</th><th>目标网址</th><th>执行状态</th><th>检查进度</th><th>创建时间</th><th>快捷操作</th></tr></thead><tbody>';
                tasks.slice(0, 5).forEach(t => {
                    html += `<tr>
                        <td><strong>${escapeHtml(t.name)}</strong><br><span style="font-size:11px; color:#64748b;">${escapeHtml(t.id)}</span></td>
                        <td><code style="color:#0284c7; cursor:pointer;" onclick="openTaskDetailsView(${safeInlineArg(t.id)})">${escapeHtml(t.target_url)}</code></td>
                        <td><span class="tag ${t.status === 'COMPLETED' ? 'tag-low' : (t.status === 'RUNNING' ? 'tag-medium' : 'tag-info')}">${t.status === 'COMPLETED' ? '已完成' : (t.status === 'RUNNING' ? '检查中' : escapeHtml(t.status))}</span></td>
                        <td style="width:160px;">
                            <div style="font-size:11px; color:#64748b;">${escapeHtml(t.current_stage || '')} (${escapeHtml(t.progress)}%)</div>
                            <div class="progress-bar"><div class="progress-val" style="width:${t.progress}%"></div></div>
                        </td>
                        <td>${escapeHtml((t.created_at || '').replace('T', ' ').substring(0, 19))}</td>
                        <td>
                            <div style="display:flex; gap:6px;">
                                <button class="btn btn-primary" style="font-size:11px; padding:3px 8px;" onclick="openTaskDetailsView(${safeInlineArg(t.id)})">🔍 详情与报文</button>
                                ${t.status === 'COMPLETED' ? `<button class="btn" style="font-size:11px; padding:3px 8px;" onclick="window.open(${safeInlineArg(`/api/v1/reports/${t.id}/html`)})">📄 查看浅色报告</button>` : ''}
                                <button class="btn" style="font-size:11px; padding:3px 8px; color:#dc2626; border-color:#fecdd3; background:#fff1f2;" onclick="deleteTaskDirect(${safeInlineArg(t.id)})">🗑️ 删除</button>
                            </div>
                        </td>
                    </tr>`;
                });
                html += '</tbody></table>';
                recentBox.innerHTML = html;
            }
        }
    } catch (e) {
        console.error('Failed to load dashboard:', e);
    }
}

async function deleteTaskDirect(id) {
    if (!confirm('确定要删除这个任务吗？相关报告和漏洞也将一并删除。')) return;
    try {
        await fetch(`${API_BASE}/tasks/${id}`, { method: 'DELETE' });
        loadDashboardData();
    } catch (e) {
        console.error('删除任务失败:', e);
    }
}

async function triggerQuickScan() {
    const url = document.getElementById('quick-target-url').value.trim();
    if (!url) return alert('请输入目标网址');
    let targetHost = '';
    try {
        targetHost = new URL(url).hostname;
    } catch (e) {
        return alert('请输入完整的 http/https 网址');
    }
    if (!confirm(`请确认已获得对域名【${targetHost}】的巡检授权。本次任务只允许访问该域名及其子域。`)) return;
    
    try {
        const res = await fetch(`${API_BASE}/tasks`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: `即时巡检 - ${url}`,
                target_url: url,
                auth_domains: [targetHost],
                max_depth: taskConfig.max_depth.default,
                max_pages: taskConfig.max_pages.default,
                qps_limit: taskConfig.qps_limit.default
            })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail ? JSON.stringify(data.detail) : `HTTP ${res.status}`);
        alert(`已成功创建巡检任务！智能体已在后台全自动执行。`);
        openTaskDetailsView(data.id);
    } catch (e) {
        alert('启动巡检失败: ' + e);
    }
}

/* ---------------- 2. AGENT CONSOLE ---------------- */
function getAgentHTML() {
    return `
    <div class="grid-2">
        <div class="chat-box">
            <div class="chat-messages" id="chat-messages">
                <div class="chat-msg msg-agent">
                    👋 您好！我是 <strong>DAS-SentinelAgent (安恒星巡安全助手)</strong>。<br>
                    您不需要写复杂的脚本，直接用大白话告诉我您想检查什么网站即可。<br><br>
                    <strong>💡 您可以点击下方快捷指令，或直接在输入框打字：</strong>
                </div>
            </div>
            <div style="display:flex; gap:6px; flex-wrap:wrap; padding:8px 12px; background:#f8fafc; border-top:1px solid #e2e8f0;">
                <button class="btn" style="font-size:11px; padding:3px 8px;" onclick="sendQuickPrompt('对 http://127.0.0.1:8088 启动全量深度合规巡检，排查身份证与手机号泄露')">🎯 检查示范靶场 8088</button>
                <button class="btn" style="font-size:11px; padding:3px 8px;" onclick="sendQuickPrompt('帮我排查目标网站有没有被黑客挂暗链或挖矿脚本')">⚠️ 查暗链和挂马</button>
                <button class="btn" style="font-size:11px; padding:3px 8px;" onclick="sendQuickPrompt('帮我比对最近两次巡检，看看修好了哪些漏洞')">⚖️ 比对历史巡检</button>
            </div>
            <div class="chat-input-bar">
                <input type="text" id="agent-input" class="form-input" placeholder="输入你想做的事 (例如：帮我检查 8088 靶场有没有泄露身份证)...">
                <button id="agent-send-btn" class="btn btn-primary">发送指令</button>
            </div>
        </div>

        <div class="card" style="display:flex; flex-direction:column; height:520px;">
            <div class="card-title"><span>🧠 智能体思考与工具调用过程 (清晰可见)</span></div>
            <div id="agent-trace-box" style="flex:1; overflow-y:auto; background:#f8fafc; border-radius:8px; padding:16px; font-size:12px; color:#334155; border:1px solid #e2e8f0;">
                <p style="color:#64748b;">等待指令下达中... 下达指令后，这里会实时展示智能体的「思考过程 ➡️ 调用的安全工具 ➡️ 观测结果」。</p>
            </div>
        </div>
    </div>
    `;
}

function sendQuickPrompt(promptText) {
    const input = document.getElementById('agent-input');
    if (input) {
        input.value = promptText;
        document.getElementById('agent-send-btn').click();
    }
}

function initAgentEvents() {
    const input = document.getElementById('agent-input');
    const btn = document.getElementById('agent-send-btn');
    if (!btn || !input) return;
    
    const send = async () => {
        const text = input.value.trim();
        if (!text) return;
        
        input.value = '';
        const msgBox = document.getElementById('chat-messages');
        const traceBox = document.getElementById('agent-trace-box');
        
        msgBox.innerHTML += `<div class="chat-msg msg-user">${escapeHtml(text)}</div>`;
        msgBox.scrollTop = msgBox.scrollHeight;
        
        traceBox.innerHTML = `<p style="color:#0284c7;">⚡ 智能体正在解析自然语言意图，并自主编排安全探针工具...</p>`;
        
        try {
            const res = await fetch(`${API_BASE}/agent/chat`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ prompt: text })
            });
            const data = await res.json();
            
            let traceHtml = `<h4 style="color:#0284c7; margin-bottom:10px;">📋 智能体生成的执行计划</h4><ol style="padding-left:20px; margin-bottom:16px;">`;
            (data.plan_steps || []).forEach(s => {
                traceHtml += `<li><strong>${escapeHtml(s.action)}</strong>: ${escapeHtml(s.description)}</li>`;
            });
            traceHtml += `</ol><h4 style="color:#0f172a; margin-bottom:10px;">🔍 思考与工具调用轨迹</h4>`;
            (data.execution_trace || []).forEach(t => {
                traceHtml += `<div class="trace-step" style="background:#ffffff; border:1px solid #e2e8f0; border-radius:6px; padding:10px; margin-bottom:8px;">
                    <div style="color:#0284c7; font-weight:600;">💭 思考: ${escapeHtml(t.thought)}</div>
                    <div style="color:#b45309; margin-top:4px;">🛠️ 工具: <code>${escapeHtml(t.tool)}</code></div>
                    <div style="color:#15803d; margin-top:4px;">👀 观测: ${escapeHtml(t.observation)}</div>
                </div>`;
            });
            traceBox.innerHTML = traceHtml;
            traceBox.scrollTop = traceBox.scrollHeight;

            const formatted = escapeHtml(data.response || '').replace(/\n/g, '<br>');
            msgBox.innerHTML += `<div class="chat-msg msg-agent">${formatted}</div>`;
            msgBox.scrollTop = msgBox.scrollHeight;
        } catch (e) {
            msgBox.innerHTML += `<div class="chat-msg msg-agent" style="border-color:#dc2626; color:#dc2626;">❌ 执行异常: ${escapeHtml(e)}</div>`;
        }
    };

    btn.onclick = send;
    input.onkeypress = (e) => { if (e.key === 'Enter') send(); };
}

/* ---------------- 3. TASKS ---------------- */
function getTasksHTML() {
    return `
    <div class="card" style="margin-bottom:20px;">
        <div class="card-title"><span>➕ 创建新的巡检任务</span></div>
        <div class="grid-4" style="margin-bottom:10px;">
            <div class="form-group">
                <label class="form-label">任务名称</label>
                <input type="text" id="task-name" class="form-input" placeholder="例如：某市政务门户季度安全巡检">
            </div>
            <div class="form-group">
                <label class="form-label">目标网站网址</label>
                <input type="text" id="task-url" class="form-input" placeholder="输入已获授权的网站网址" value="">
            </div>
            <div class="form-group">
                <label class="form-label">授权域名白名单 (逗号隔开)</label>
                <input type="text" id="task-auth" class="form-input" placeholder="例如：example.gov.cn, sub.example.gov.cn" value="">
            </div>
            <div class="form-group">
                <label class="form-label">定时自动巡检预设</label>
                <select id="task-cron-preset" class="form-select" onchange="applyCronPreset(this.value)">
                    <option value="">立即单次检查 (不开启定时)</option>
                    <option value="0 2 * * *">每天凌晨 02:00 自动查一次 (0 2 * * *)</option>
                    <option value="0 */6 * * *">每 6 小时自动查一次 (0 */6 * * *)</option>
                    <option value="0 3 * * 1">每周一凌晨 03:00 自动查一次 (0 3 * * 1)</option>
                    <option value="custom">自定义 Cron 时间表达式...</option>
                </select>
            </div>
        </div>
        <div class="form-group" id="custom-cron-group" style="display:none; margin-bottom:10px;">
            <label class="form-label">自定义 Cron 表达式 (分 时 日 月 星期)</label>
            <input type="text" id="task-cron" class="form-input" placeholder="例如：*/30 * * * * (每30分钟一次)">
        </div>
        <div class="form-group" style="margin-bottom:12px;">
            <label class="form-label">单位内部敏感词/保密代号 (逗号隔开，选填)</label>
            <input type="text" id="task-keywords" class="form-input" placeholder="例如：内部绝密, 薪酬表, 核心秘钥, 工单清单">
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px;">
            <div style="font-size:12px; color:#64748b;">
                🛡️ 安全合规保障：最大深度 3 层 | 抓取最多 100 页面 | 限速 5 QPS | 严格只读无害探测，绝不搞垮网站
            </div>
            <button class="btn btn-primary" onclick="createTask()">提交并开始检查</button>
        </div>
    </div>

    <div class="card">
        <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <span>📋 巡检任务列表与历史记录</span>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#f0fdf4; color:#15803d; border-color:#bbf7d0;" onclick="cleanupKeepLatestTasks()" title="每个目标网站仅保留最新 1 次巡检记录，自动清除旧冗余任务">🧹 一键精简历史冗余 (保留各目标最新基线)</button>
                <button class="btn" style="font-size:11px; padding:3px 10px; color:#dc2626;" onclick="cleanupAllCompletedTasks()">🗑️ 清理已完成记录</button>
                <button class="btn" style="font-size:11px; padding:3px 10px;" onclick="loadTasksTable()">🔄 刷新列表</button>
            </div>
        </div>
        <div id="tasks-table-box">正在加载任务...</div>
    </div>
    `;
}

window.cleanupKeepLatestTasks = async function() {
    if (!confirm('确定要一键精简冗余历史任务吗？\n系统将自动保留每个目标网站最新的 1 次巡检基线，清除所有冗余旧任务。')) {
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/tasks/cleanup/keep-latest`, { method: 'POST' });
        const data = await res.json();
        alert(data.message || '清理完成！');
        loadTasksTable();
        loadDashboardStats();
    } catch (e) {
        alert('清理失败: ' + e);
    }
};

window.cleanupAllCompletedTasks = async function() {
    if (!confirm('确定要清空所有已完成的历史任务记录吗？')) {
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/tasks/cleanup/all-completed`, { method: 'POST' });
        const data = await res.json();
        alert(data.message || '已清空历史任务！');
        loadTasksTable();
        loadDashboardStats();
    } catch (e) {
        alert('清理失败: ' + e);
    }
};

function applyCronPreset(val) {
    const customGroup = document.getElementById('custom-cron-group');
    const customInput = document.getElementById('task-cron');
    if (val === 'custom') {
        customGroup.style.display = 'block';
        customInput.value = '';
    } else {
        customGroup.style.display = 'none';
        customInput.value = val;
    }
}

async function loadTasksTable() {
    try {
        const res = await fetch(`${API_BASE}/tasks`);
        const tasks = await res.json();
        const box = document.getElementById('tasks-table-box');
        if (!box) return;
        
        if (tasks.length === 0) {
            box.innerHTML = '<p style="color:#64748b; font-size:13px; padding:16px 0;">暂无巡检任务</p>';
            return;
        }

        let html = `<table class="data-table">
            <thead>
                <tr>
                    <th>任务名称 / ID</th>
                    <th>目标网址</th>
                    <th>执行周期</th>
                    <th>状态</th>
                    <th>当前进度</th>
                    <th>安全评分</th>
                    <th>创建时间</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>`;
        let hasRunningTasks = false;
        tasks.forEach(t => {
            if (t.status === 'RUNNING' || t.status === 'PENDING') {
                hasRunningTasks = true;
            }
            const score = t.summary ? (t.summary.security_score !== undefined ? t.summary.security_score : '--') : '--';
            const scoreColor = typeof score === 'number' ? (score < 60 ? '#dc2626' : (score < 85 ? '#d97706' : '#16a34a')) : '#64748b';
            const cronText = t.cron_expr ? `<span class="tag tag-medium">⏰ ${escapeHtml(t.cron_expr)}</span>` : '<span style="color:#64748b; font-size:11px;">单次</span>';
            html += `<tr>
                <td><strong>${escapeHtml(t.name)}</strong><br><span style="font-size:11px; color:#64748b;">${escapeHtml(t.id)}</span></td>
                <td><code style="color:#0284c7; cursor:pointer;" onclick="openTaskDetailsView(${safeInlineArg(t.id)})">${escapeHtml(t.target_url)}</code></td>
                <td>${cronText}</td>
                <td><span class="tag ${t.status === 'COMPLETED' ? 'tag-low' : (t.status === 'RUNNING' ? 'tag-medium' : 'tag-info')}">${t.status === 'COMPLETED' ? '已完成' : (t.status === 'RUNNING' ? '检查中' : escapeHtml(t.status))}</span></td>
                <td style="width:180px;">
                    <div style="font-size:11px; color:#64748b;">${escapeHtml(t.current_stage || '')} (${escapeHtml(t.progress)}%)</div>
                    <div class="progress-bar"><div class="progress-val" style="width:${t.progress}%"></div></div>
                </td>
                <td><strong style="color:${scoreColor}">${escapeHtml(score)} 分</strong></td>
                <td>${escapeHtml((t.created_at || '').replace('T', ' ').substring(0, 19))}</td>
                <td>
                    <div style="display:flex; gap:6px;">
                        <button class="btn btn-primary" style="font-size:11px; padding:3px 8px;" onclick="openTaskDetailsView(${safeInlineArg(t.id)})">🔍 详情与报文</button>
                        ${t.status === 'COMPLETED' ? `<button class="btn" style="font-size:11px; padding:3px 8px;" onclick="window.open(${safeInlineArg(`/api/v1/reports/${t.id}/html`)})">📄 浅色报告</button>` : ''}
                        <button class="btn" style="font-size:11px; padding:3px 8px;" onclick="rerunTask(${safeInlineArg(t.id)})">重新检查</button>
                        <button class="btn" style="font-size:11px; padding:3px 8px; color:#dc2626;" onclick="deleteTask(${safeInlineArg(t.id)})">删除</button>
                    </div>
                </td>
            </tr>`;
        });
        html += `</tbody></table>`;
        box.innerHTML = html;

        // 如果有正在运行的任务，自动每 3 秒刷新一次列表进度
        if (hasRunningTasks && currentTab === 'tasks' && !currentDetailTaskId) {
            setTimeout(loadTasksTable, 3000);
        }
    } catch (e) {
        console.error(e);
    }
}

async function createTask() {
    const name = document.getElementById('task-name').value.trim() || '巡检任务-' + new Date().toLocaleTimeString();
    const url = document.getElementById('task-url').value.trim();
    const auth = document.getElementById('task-auth').value.split(',').map(s => s.trim()).filter(Boolean);
    const cron = document.getElementById('task-cron').value.trim();
    const keywords = (document.getElementById('task-keywords')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!url) return alert('请填写已获授权的目标 URL');
    if (!auth.length) return alert('请至少填写一个已获授权的域名');

    try {
        const res = await fetch(`${API_BASE}/tasks`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                target_url: url,
                auth_domains: auth,
                cron_expr: cron,
                custom_sensitive_keywords: keywords,
                max_depth: taskConfig.max_depth.default,
                max_pages: taskConfig.max_pages.default,
                qps_limit: taskConfig.qps_limit.default
            })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail ? JSON.stringify(data.detail) : `HTTP ${res.status}`);
        alert('巡检任务创建成功！智能体正在后台全自动执行。');
        openTaskDetailsView(data.id);
    } catch (e) {
        alert('创建失败: ' + e);
    }
}

async function rerunTask(id) {
    const res = await fetch(`${API_BASE}/tasks/${id}/rerun`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) return alert(`重新检查失败: ${data.detail || res.status}`);
    if (data.task_id) openTaskDetailsView(data.task_id);
    else loadTasksTable();
}

async function retestAllTask(id) {
    await rerunTask(id);
}

async function deleteTask(id) {
    if (!confirm('确定删除该任务及其所有检查记录吗？')) return;
    await fetch(`${API_BASE}/tasks/${id}`, { method: 'DELETE' });
    if (currentDetailTaskId === id) {
        currentDetailTaskId = null;
        renderTabContent('tasks');
    } else {
        loadTasksTable();
    }
}

/* ---------------- ⚡ BURP SUITE SCANNER 深度巡检详情页核心实现 ---------------- */
async function openTaskDetailsView(taskId, focusUrl = null, focusFindingId = null) {
    currentDetailTaskId = taskId;
    focusPageUrl = focusUrl || null;
    selectedFindingIndex = 0;
    selectedTopologyFindingIndex = 0;
    selectedTopologyNodeId = null;
    currentBurpSubTab = 'sitemap';
    currentHttpViewTab = 'request';
    currentSitemapFilter = 'ALL';
    selectedLogItem = null;
    
    document.getElementById('tab-title').innerText = `巡检详情 (Burp Scanner 视图) - [${taskId}]`;
    const container = document.getElementById('main-content');
    container.innerHTML = `<div style="text-align:center; padding:50px; color:#0284c7;">⚡ 正在加载任务巡检与 HTTP 流量证据链...</div>`;
    
    await refreshTaskDetailsLive();
}

function clearFocusPage() {
    focusPageUrl = null;
    selectedTopologyFindingIndex = 0;
    selectedFindingIndex = 0;
    renderBurpScannerLayout(currentTaskDetailData);
}

async function refreshTaskDetailsLive() {
    if (!currentDetailTaskId) return;
    try {
        let data = null;
        const res = await fetch(`${API_BASE}/tasks/${currentDetailTaskId}/details`);
        if (res.ok) {
            data = await res.json();
        } else {
            // 兼容性回退
            const [taskRes, findingsRes, logsRes] = await Promise.all([
                fetch(`${API_BASE}/tasks/${currentDetailTaskId}`),
                fetch(`${API_BASE}/findings?task_id=${currentDetailTaskId}`),
                fetch(`${API_BASE}/reports/audit-logs?limit=30`)
            ]);
            const task = await taskRes.json();
            const findings = await findingsRes.json();
            const logs = await logsRes.json();
            
            findings.forEach(f => {
                const targetUrl = f.url || '';
                let path = '/';
                let host = 'target';
                try {
                    const u = new URL(targetUrl);
                    path = u.pathname + u.search;
                    host = u.host;
                } catch(e) {}
                
                const reqH = f.evidence?.request_headers || {};
                let reqStr = `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: DAS-SentinelAgent/1.0 (Security Inspector; DAS-AI)\r\nAccept: */*\r\nConnection: close\r\n`;
                for (const [k, v] of Object.entries(reqH)) {
                    reqStr += `${k}: ${v}\r\n`;
                }
                f.raw_request = reqStr;
                
                const respH = f.evidence?.response_headers || {};
                const respStatus = f.evidence?.response_status;
                let respStr = respStatus === undefined || respStatus === null
                    ? '[未保存原始 HTTP 响应]\r\n'
                    : `HTTP/1.1 ${respStatus}\r\n`;
                for (const [k, v] of Object.entries(respH)) {
                    respStr += `${k}: ${v}\r\n`;
                }
                respStr += `\r\n${f.evidence?.matched_snippet || ''}`;
                f.raw_response = respStr;
            });
            
            data = {
                task: task,
                findings_count: findings.length,
                findings: findings,
                sitemap_count: task.summary?.total_pages_scanned || 1,
                sitemap: [{ url: task.target_url, title: task.name, status: null, type: 'PAGE' }],
                audit_logs: logs,
                architecture: task.summary?.architecture || null
            };
        }
        
        // 避免在任务已完成且数据无变化时重复重新渲染导致大卡片抽搐闪烁
        if (currentTaskDetailData && currentTaskDetailData.task && currentTaskDetailData.task.status === 'COMPLETED' && data && data.task && data.task.status === 'COMPLETED') {
            if ((currentTaskDetailData.findings || []).length === (data.findings || []).length && (currentTaskDetailData.sitemap || []).length === (data.sitemap || []).length) {
                return; // 数据完全一致，静默保持，绝不重新渲染破坏用户交互
            }
        }
        
        currentTaskDetailData = data;
        renderBurpScannerLayout(data);
    } catch (e) {
        console.error('Failed to refresh task details:', e);
    }
}

// 根据任务快照渲染架构；接口降级时明确显示“未识别”，不填充猜测值。
function getArchitectureData(task, sitemap, findings, serverArch) {
    if (serverArch && serverArch.layers && serverArch.layers.length > 0) {
        return serverArch;
    }

    // 旧任务或接口降级时只展示“未识别”，不按域名猜测框架、网关、数据库或 TLS 版本。
    const targetUrl = task ? (task.target_url || '') : '';
    let targetHost = targetUrl;
    try { targetHost = new URL(targetUrl).hostname || targetUrl; } catch (e) { /* 保留原始值 */ }
    return {
        target_host: targetHost,
        target_url: targetUrl,
        analyzed_pages_count: Array.isArray(sitemap) ? sitemap.length : 0,
        layers: [],
        cpe_candidates: [],
        fingerprint_policy: 'EVIDENCE_ONLY',
        evidence_note: '当前任务未保存足够的响应指纹，未对技术栈进行猜测。'
    };
}

// 只根据后端保存的架构指纹和巡检资产绘制拓扑；未知组件明确标记为未识别。
function generateObservedTopology(task, sitemap, findings, architecture) {
    const layers = Array.isArray(architecture?.layers) ? architecture.layers : [];
    const ids = ['frontend', 'cdn', 'backend', 'db', 'auth'];
    const positions = [
        [180, 170], [420, 170], [660, 170], [900, 170], [1140, 170]
    ];
    const nodes = [{
        id: 'user',
        title: '🧑 授权巡检访问端',
        subTitle: 'Observed Request Origin',
        tech: 'HTTP(S) 客户端',
        desc: '由本系统在授权范围内发起受限、可审计的巡检请求。',
        svgX: 60, svgY: 170,
        details: {
            framework: '未识别', protocol: 'HTTP/HTTPS', assets: '巡检请求',
            securityPolicy: '授权域名白名单与限速', threatSurface: '请求边界由任务授权配置决定',
            hardening: '仅对明确授权的域名执行巡检。', compliance: '授权测试与最小权限原则。'
        }
    }];
    ids.forEach((id, index) => {
        const layer = layers[index] || {};
        const component = layer.component || {};
        const detected = component.detected === true;
        const name = component.name || '未识别组件';
        const version = component.version || '版本未知';
        const evidence = Array.isArray(component.evidence) ? component.evidence : [];
        const position = positions[index];
        nodes.push({
            id,
            title: `${layer.title || `第 ${index + 1} 层`} · ${name}`,
            subTitle: layer.role || 'Observed Architecture Layer',
            tech: detected ? `${name}${version && version !== '版本未知' ? ` ${version}` : ''}` : '未识别（证据不足）',
            desc: component.details || '未获得可复核的组件识别证据。',
            svgX: position[0], svgY: position[1],
            details: {
                framework: detected ? name : '未识别',
                protocol: '未观测',
                assets: `${Array.isArray(sitemap) ? sitemap.length : 0} 个已发现页面/资产`,
                securityPolicy: detected ? `识别置信度 ${component.confidence || '未知'}` : '未观测到可复核指纹',
                threatSurface: `${Array.isArray(findings) ? findings.length : 0} 项巡检发现关联到当前任务`,
                hardening: '请基于响应证据、风险详情与复测结果制定加固措施。',
                compliance: '当前拓扑仅反映已观测证据，不替代资产台账或人工架构确认。',
                evidence
            }
        });
    });
    const edges = ids.map((id, index) => ({
        from: index === 0 ? 'user' : ids[index - 1],
        to: id,
        key: `${index === 0 ? 'user' : ids[index - 1]}-${id}`,
        label: index === 0 ? '授权 HTTP(S) 请求' : '观测层级关联（示意）'
    }));
    return {
        profileType: 'OBSERVED_EVIDENCE',
        profileTitle: '基于巡检证据的观测拓扑（未知组件不猜测）',
        nodes,
        edges
    };
}

// 🌐 随不同目标网站特征自适应生成架构拓扑 (Site-Adaptive Topology Architecture)
function generateSiteAdaptiveTopology(task, sitemap, findings) {
    const targetUrl = task ? (task.target_url || '') : '';
    const isVercel = targetUrl.includes('vercel.app') || targetUrl.includes('vercel');
    const isLocalLab = targetUrl.includes('8088') || targetUrl.includes('127.0.0.1');
    const isSpringMicro = targetUrl.includes('java') || targetUrl.includes('spring') || targetUrl.includes('8080');

    let profileType = 'STANDARD_WEB';
    let profileTitle = '政企门户/Web 应用标准分层架构 (Standard Enterprise Web)';
    if (isVercel) {
        profileType = 'CLOUD_SERVERLESS';
        profileTitle = '现代云原生 Serverless / Edge 边缘架构 (Vercel / Cloud Edge)';
    } else if (isSpringMicro) {
        profileType = 'ENTERPRISE_MICROSERVICES';
        profileTitle = '企业级微服务与分布式中台架构 (Spring Cloud / Microservices)';
    }

    let nodes = [];
    let edges = [];

    if (profileType === 'CLOUD_SERVERLESS') {
        // 云原生 Serverless 专属动态拓扑 (Vercel / Next.js)
        nodes = [
            // Row 1: 客户端
            {
                id: 'user',
                title: '🧑 客户端终端 (SPA/Browser)',
                subTitle: 'Modern Browser & Client Execution',
                tech: 'Chrome / Safari (V8 Engine)',
                desc: 'SPA 路由分发、客户端组件 Hydration 与异步 Fetch 请求',
                xPercent: 50, yPercent: 10, svgX: 550, svgY: 85,
                details: {
                    framework: 'React 18 / Next.js 客户端组件 / ES2024',
                    protocol: 'HTTPS / TLS 1.3 / HTTP/3 (QUIC) / Server-Sent Events',
                    assets: '浏览器 LocalStorage, WebAssembly, ServiceWorker',
                    securityPolicy: 'Strict CSP, SameSite Cookie, 子资源完整性 (SRI)',
                    threatSurface: '客户端 XSS 跨站脚本、敏感 Token 本地明文存储外泄',
                    hardening: '配置严密 Content-Security-Policy 并禁止在客户端暴露私密 Token。',
                    compliance: '《网络安全法》：保障客户端数据完整性与传输机密性。'
                }
            },
            // Row 2: 边缘计算与静态加速
            {
                id: 'edge_cdn',
                title: '⚡ Vercel Edge 边缘网络',
                subTitle: 'Global Anycast CDN & Edge Middleware',
                tech: 'Vercel Edge Network / Cloudflare Anycast',
                desc: '全球 300+ 边缘节点智能路由、动态边缘中间件与 DDoS 流量过滤',
                xPercent: 25, yPercent: 35, svgX: 275, svgY: 300,
                details: {
                    framework: 'Vercel Distributed Edge Network (Anycast BGP)',
                    protocol: 'HTTP/3 (QUIC / 443) / Anycast DNS / TLS 1.3 0-RTT',
                    assets: '边缘分块静态资源缓存, 边缘中间件路由表, DDoS 防护探针',
                    securityPolicy: 'Anycast DDoS 流量清洗, CC 防御与速率限制, SSL 自动续期',
                    threatSurface: '源站配置不当导致的边缘缓存穿透与缓存投毒',
                    hardening: '开启 Edge Cache Shield 并对 API 路由实施细粒度鉴权。',
                    compliance: '等保 2.0：具备网络边界防护与抗拒绝服务攻击能力。'
                }
            },
            {
                id: 'frontend_ssr',
                title: '⚛️ Next.js SSR / React 18',
                subTitle: 'Server-Side Rendering & Client Bundle',
                tech: 'Next.js 14+ (App Router / React 18)',
                desc: '服务端渲染 SSR、React Server Components (RSC) 与静态增量再生 (ISR)',
                xPercent: 75, yPercent: 35, svgX: 825, svgY: 300,
                details: {
                    framework: 'Next.js App Router (RSC 架构)',
                    protocol: 'Streaming SSR / JSON / RESTful / GraphQL',
                    assets: '前端组件代码库 (/app, /components), 预构建 HTML 静态块',
                    securityPolicy: '自动 HTML 转义防 XSS, 安全响应头 (HSTS/CORS/CSP)',
                    threatSurface: '敏感配置打包入前端代码包 (NEXT_PUBLIC_ 滥用)、模板注入',
                    hardening: '严禁在客户端环境变量中使用任何服务端私钥；开启生产代码混淆。',
                    compliance: '《数据安全法》：敏感数据在前端输出前必须脱敏。'
                }
            },
            // Row 3: Serverless 运行时与鉴权
            {
                id: 'serverless_func',
                title: '▲ Serverless 云函数运行时',
                subTitle: 'Serverless Functions & API Routes',
                tech: 'Node.js 20.x (V8 Isolated Runtime)',
                desc: '按需弹性伸缩微服务、API 接口控制器与 ORM 业务数据映射',
                xPercent: 25, yPercent: 65, svgX: 275, svgY: 560,
                details: {
                    framework: 'Node.js Serverless Microservice · Prisma ORM',
                    protocol: 'HTTPS / JSON / gRPC (Port: 443)',
                    assets: 'API 控制器 (/api/*), 业务服务层, 云函数环境变量配置 (.env)',
                    securityPolicy: '无状态执行环境, 最小化云 IAM 角色权限, SQL 参数化预编译',
                    threatSurface: '.env 环境变量泄露导致云平台密钥外泄、未授权越权访问',
                    hardening: '使用云平台 KMS 秘钥管理托管敏感凭据；生产环境严禁暴露 .env。',
                    compliance: '《网络安全法》：核心业务代码与数据库凭证严密防护。'
                }
            },
            {
                id: 'auth_iam',
                title: '🔑 NextAuth / JWT 认证网关',
                subTitle: 'Identity & Access Management (IAM)',
                tech: 'NextAuth.js / OAuth 2.0 / JWT RS256',
                desc: '多渠道 OAuth 登录、JWT 签名校验、用户会话 Session 安全轮转',
                xPercent: 75, yPercent: 65, svgX: 825, svgY: 560,
                details: {
                    framework: 'NextAuth.js · OAuth 2.0 / OpenID Connect',
                    protocol: 'HTTPS / Bearer Token / Encrypted JWE Cookie',
                    assets: 'JWT 签名公私钥对, 用户认证上下文, RBAC 权限控制表',
                    securityPolicy: 'HttpOnly SameSite=Lax Cookie, CSRF Token 动态校验, 令牌定期刷新',
                    threatSurface: 'JWT 空签名绕过 (alg: none)、OAuth 认证重定向劫持',
                    hardening: '强制使用非对称加密算法签名 JWT；设置严格白名单重定向域名。',
                    compliance: '等保 2.0：重要接口应具备身份鉴别与防重放机制。'
                }
            },
            // Row 4: 云端数据库与持久化
            {
                id: 'cloud_db',
                title: '🗄️ Neon Serverless Postgres',
                subTitle: 'Cloud Relational Database Cluster',
                tech: 'PostgreSQL 16 (Serverless Branching)',
                desc: '业务主表持久化、用户账户凭据、资产数据与安全事件日志存储',
                xPercent: 30, yPercent: 90, svgX: 330, svgY: 775,
                details: {
                    framework: 'PostgreSQL 16 · MVCC 事务引擎',
                    protocol: 'PostgreSQL Wire Protocol (SSL 强制加密)',
                    assets: '核心业务数据表, 用户账户凭证, 巡检记录表, 审计日志流',
                    securityPolicy: '连接池 SSL 传输加密, 行级安全策略 (RLS), 自动快照全备',
                    threatSurface: 'SQL 注入导致数据库全量脱库、DATABASE_URL 密码明文泄露',
                    hardening: '强制开启 Prisma/TypeORM 参数化绑定；数据库仅允许云函数内网白名单直连。',
                    compliance: '《数据安全法》：对核心数据库实施严格分级保护与审计。'
                }
            },
            {
                id: 'blob_storage',
                title: '📁 Vercel Blob / AWS S3 存储',
                subTitle: 'Cloud Object Storage Service',
                tech: 'Vercel Blob / Cloud S3',
                desc: '静态大文件、用户附件池、评估报告 HTML 归档与多媒体资产存储',
                xPercent: 70, yPercent: 90, svgX: 770, svgY: 775,
                details: {
                    framework: 'Cloud Object Storage · Presigned URL 签名机制',
                    protocol: 'HTTPS RESTful API (Port: 443)',
                    assets: '用户上传文件池, 历史评估报告归档, 网站静态附件包',
                    securityPolicy: '私有 Bucket 读写隔离, 临时 STS Token 鉴权, 上传 MIME 白名单',
                    threatSurface: 'Bucket 权限公开导致文件被黑客批量下载或恶意篡改',
                    hardening: '存储桶默认设为 Private 私有；上传文件重新命名为随机 UUID 散列。',
                    compliance: '《个人信息保护法》：附件中敏感个人信息分类管理与加密防护。'
                }
            }
        ];

        edges = [
            { from: 'user', to: 'edge_cdn', key: 'user-edge_cdn', label: '1. HTTPS 访问 ➔' },
            { from: 'user', to: 'frontend_ssr', key: 'user-frontend_ssr', label: 'SPA 路由分发 ➔' },
            { from: 'edge_cdn', to: 'frontend_ssr', key: 'edge_cdn-frontend_ssr', label: '静态加速缓存 ➔' },
            { from: 'frontend_ssr', to: 'auth_iam', key: 'frontend_ssr-auth_iam', label: '2. 身份鉴权调用 ➔' },
            { from: 'frontend_ssr', to: 'serverless_func', key: 'frontend_ssr-serverless_func', label: '3. API 云函数处理 ➔' },
            { from: 'auth_iam', to: 'serverless_func', key: 'auth_iam-serverless_func', label: '鉴权通过路由 ➔' },
            { from: 'serverless_func', to: 'cloud_db', key: 'serverless_func-cloud_db', label: '4. 数据库事务读写 ➔' },
            { from: 'serverless_func', to: 'blob_storage', key: 'serverless_func-blob_storage', label: '附件文件存取 ➔' }
        ];
    } else {
                        // 标准政企与传统企业级 Web 架构 (127.0.0.1:8088 / 政企标准靶场) - 扩展为 21 节点分层架构 (1200px 黄金紧凑舒展高度)
        nodes = [
            // ================= Tier 1: 客户端层 (Y = 60) =================
            {
                id: 'user', title: '🧑 终端用户浏览器 / APP', subTitle: 'Client Presentation & User Agent',
                tech: 'Chrome / iOS / Android', desc: '发起合法或恶意探测请求的攻击端点。',
                svgX: 600, svgY: 60,
                details: { framework: 'V8 / WebKit', protocol: 'HTTPS / TLS 1.3', assets: 'LocalStorage, 离线缓存', securityPolicy: '同源策略, CSP, HttpOnly', threatSurface: 'XSS, CSRF, Token 泄露', hardening: 'CSP 配置严格白名单。', compliance: '《网络安全法》通信机密性保障。' }
            },

            // ================= Tier 2: 边缘调度与流量接入 (Y = 210) =================
            {
                id: 'dns', title: '🌍 智能 DNS 调度中心', subTitle: 'Global Traffic Manager (GTM)',
                tech: 'Anycast DNS / GSLB', desc: '全球多活机房流量调度与探针智能解析。',
                svgX: 200, svgY: 210,
                details: { framework: 'Bind9 / Cloud DNS', protocol: 'UDP 53 / DoH', assets: '域名解析记录', securityPolicy: 'DNSSEC', threatSurface: 'DNS 劫持、缓存投毒', hardening: '开启 DNSSEC 防止欺骗。', compliance: '《关键信息基础设施安全保护条例》' }
            },
            {
                id: 'cdn', title: '⚡ CDN 静态边缘分发', subTitle: 'Edge Content Delivery Network',
                tech: '边缘缓存节点', desc: '静态资源 HTML/CSS/JS 全球边缘缓存。',
                svgX: 600, svgY: 210,
                details: { framework: 'Edge Cache / Nginx', protocol: 'HTTP/2 / QUIC', assets: '静态大文件包', securityPolicy: '节点限速与防盗链', threatSurface: '缓存击穿、敏感文件缓存', hardening: 'API 接口配置 No-Cache。', compliance: '等保 2.0 第三级要求。' }
            },
            {
                id: 'ddos', title: '🛡️ 抗 DDoS 清洗中心', subTitle: 'Anti-DDoS Scrubbing Center',
                tech: '黑洞路由 / BGP Anycast', desc: '流量清洗，抵御海量 CC 与反射型放大攻击。',
                svgX: 1000, svgY: 210,
                details: { framework: 'BGP 牵引清洗', protocol: 'TCP/UDP', assets: '防护策略组', securityPolicy: '七层与四层流量过滤', threatSurface: '清洗节点被打穿', hardening: '自动切换备用高防 IP。', compliance: '等保高抗攻击要求。' }
            },

            // ================= Tier 3: 边界接入与安全防护 (Y = 380) =================
            {
                id: 'lb', title: '⚖️ 四/七层负载均衡', subTitle: 'Load Balancer / Ingress',
                tech: 'LVS / HAProxy / Nginx', desc: '集中解密 SSL/TLS 并将请求分发至内网。',
                svgX: 160, svgY: 380,
                details: { framework: 'HAProxy / K8s Ingress', protocol: 'HTTPS', assets: 'SSL 证书对', securityPolicy: 'HSTS 严格传输加密', threatSurface: 'SSL 证书泄露、降级攻击', hardening: '禁用旧版本 TLS 1.1。', compliance: '密码法要求加密通道。' }
            },
            {
                id: 'frontend', title: '💻 网页前端 SPA', subTitle: 'Web Frontend Application',
                tech: 'React / Vue / Nginx', desc: '展现政企门户应用与异步数据获取。',
                svgX: 450, svgY: 380,
                details: { framework: 'Vue 3 / Webpack', protocol: 'REST / GraphQL', assets: '前端源代码 (.map)', securityPolicy: 'DOMPurify 过滤', threatSurface: '源码泄露、API 密钥硬编码', hardening: '构建时移除 .map 文件。', compliance: '防前端逆向要求。' }
            },
            {
                id: 'waf', title: '🧱 WAF Web 防火墙', subTitle: 'Web Application Firewall',
                tech: 'ModSecurity / CloudWAF', desc: '深度包检测，拦截 OWASP Top 10 漏洞攻击。',
                svgX: 750, svgY: 380,
                details: { framework: '动态规则与语义分析', protocol: 'HTTP', assets: '黑名单策略库', securityPolicy: '注入与 XSS 阻断', threatSurface: '特制编码绕过防护规则', hardening: '保持漏洞库每日更新。', compliance: '等保边界过滤要求。' }
            },
            {
                id: 'vpn', title: '🔒 零信任网关 / VPN', subTitle: 'Zero Trust Network Access',
                tech: 'IPsec / SSL VPN', desc: '员工远程办公与管理后台专线接入鉴权。',
                svgX: 1040, svgY: 380,
                details: { framework: 'ZTNA / OpenVPN', protocol: 'IPsec', assets: '员工身份证书', securityPolicy: '多因素 MFA 验证', threatSurface: 'VPN 漏洞被 RCE', hardening: '强制 MFA 扫码二次认证。', compliance: '国密算法接入要求。' }
            },

            // ================= Tier 4: 微服务网关与鉴权中心 (Y = 560) =================
            {
                id: 'auth', title: '🔑 IAM 认证中心', subTitle: 'Identity & Access Mgt.',
                tech: 'OAuth 2.0 / JWT', desc: '统一 SSO 登录，颁发与验证访问令牌。',
                svgX: 200, svgY: 560,
                details: { framework: 'Keycloak / Spring Security', protocol: 'OIDC / JWT', assets: 'JWT 签名私钥', securityPolicy: '短效 Token 与防重放', threatSurface: '空签名绕过、越权', hardening: '强制 RS256 加密签名。', compliance: '等保身份鉴别要求。' }
            },
            {
                id: 'api_gw', title: '🚪 API 集中网关', subTitle: 'API Gateway',
                tech: 'Kong / APISIX', desc: '服务路由、统一限流与内网熔断降级。',
                svgX: 600, svgY: 560,
                details: { framework: 'Kong / Lua', protocol: 'HTTP/gRPC', assets: '路由分发表', securityPolicy: '接口鉴权与速率限制', threatSurface: 'API 未授权访问', hardening: '阻断未携带合法鉴权的请求。', compliance: '数据安全法接口要求。' }
            },
            {
                id: 'task_sched', title: '⏱️ 任务调度中心', subTitle: 'Task Scheduler',
                tech: 'XXL-JOB / Quartz', desc: '定时执行巡检、报表生成与异步对账任务。',
                svgX: 1000, svgY: 560,
                details: { framework: 'XXL-JOB', protocol: 'RPC', assets: '定时任务脚本', securityPolicy: '脚本沙箱执行', threatSurface: '未授权下发 RCE 任务', hardening: '鉴权绕过补丁必须升级。', compliance: '安全基线要求。' }
            },

            // ================= Tier 5: 核心业务微服务与后台管理 (Y = 740) =================
            {
                id: 'backend', title: '⚙️ 核心业务微服务', subTitle: 'Core Business Microservices',
                tech: 'Spring Boot / Go', desc: '处理核心业务订单、资金与高敏感操作。',
                svgX: 460, svgY: 740,
                details: { framework: 'Spring Cloud', protocol: 'gRPC / Dubbo', assets: '业务核心代码库, .env', securityPolicy: 'ORM 参数化绑定', threatSurface: 'SQLi, RCE, 反序列化', hardening: '禁止拼接 SQL、阻断危险命令。', compliance: '安全开发生命周期要求。' }
            },
            {
                id: 'ms_admin', title: '🛠️ 后台管理服务', subTitle: 'Admin Backend Services',
                tech: 'Django / FastAPI', desc: '提供报表导出、用户封禁等超管控制台 API。',
                svgX: 860, svgY: 740,
                details: { framework: 'Django Admin', protocol: 'HTTP', assets: '超级管理员表', securityPolicy: '仅限内网与 VPN 访问', threatSurface: '未授权暴露到公网', hardening: '内网防火墙严格隔离该网段。', compliance: '后台分离审计要求。' }
            },

            // ================= Tier 6: 缓存、消息队列与主从数据库 (Y = 920) =================
            {
                id: 'cache', title: '📦 分布式缓存池', subTitle: 'Redis Cluster',
                tech: 'Redis 7.2 高可用', desc: '存储用户 Session 令牌与极速查询热点数据。',
                svgX: 160, svgY: 920,
                details: { framework: 'Redis Cluster', protocol: 'RESP', assets: '会话 Token 池', securityPolicy: '内网隔离与密码认证', threatSurface: '未授权访问直接写 Shell', hardening: '设置强密码、禁止绑定 0.0.0.0。', compliance: '等保隔离保护。' }
            },
            {
                id: 'mq', title: '📨 消息队列集群', subTitle: 'Kafka / RabbitMQ',
                tech: 'Kafka 高吞吐', desc: '削峰填谷，解耦高并发日志请求与通知。',
                svgX: 450, svgY: 920,
                details: { framework: 'Apache Kafka', protocol: 'TCP', assets: '审计日志流', securityPolicy: 'ACL 权限隔离', threatSurface: '消息窃听与篡改', hardening: '启动传输层加密。', compliance: '不可篡改审计要求。' }
            },
            {
                id: 'db', title: '🗄️ 核心主数据库', subTitle: 'Primary Relational DB',
                tech: 'MySQL 8.0 主库', desc: '事务核心，存储账号密码与最核心资产记录。',
                svgX: 750, svgY: 920,
                details: { framework: 'MySQL InnoDB', protocol: 'TCP 3306', assets: '核心用户表，交易表', securityPolicy: '自动全备与增备', threatSurface: '全量脱库、备份暴露', hardening: '备份文件切勿留在 Web 根目录。', compliance: '《数据安全法》严密防护。' }
            },
            {
                id: 'db_read', title: '🗃️ 读写分离从库', subTitle: 'Read Replica DB',
                tech: 'MySQL Slave', desc: '处理大量跨表查询的报表与分析压力。',
                svgX: 1040, svgY: 920,
                details: { framework: 'Binlog 同步', protocol: 'TCP', assets: '报表快照', securityPolicy: '只读权限 (Read Only)', threatSurface: '内网渗透后的提权', hardening: '配置应用侧只读账号。', compliance: '等保可用性与分流。' }
            },

            // ================= Tier 7: 存储运维与安全感知组件 (Y = 1100) =================
            {
                id: 'oss', title: '📁 对象存储 (OSS)', subTitle: 'Cloud Object Storage',
                tech: 'MinIO / Aliyun OSS', desc: '存储上传文件、头像、大图与扫描报告打包。',
                svgX: 130, svgY: 1100,
                details: { framework: 'S3 兼容 API', protocol: 'HTTPS', assets: '上传附件池', securityPolicy: 'Bucket 私有权限', threatSurface: 'Bucket 公开导致数据泄露', hardening: '阻断上传恶意 HTML/PHP 文件。', compliance: '个人隐私保护法。' }
            },
            {
                id: 'nosql', title: '🔎 大数据检索集群', subTitle: 'ElasticSearch',
                tech: 'ES 8.0 搜索引擎', desc: '全量日志索引、模糊搜索与分析支持。',
                svgX: 365, svgY: 1100,
                details: { framework: 'Lucene', protocol: 'HTTP', assets: '历史检索归档', securityPolicy: 'X-Pack 鉴权', threatSurface: '未授权查询窃取海量日志', hardening: '启用 X-Pack 和强密码。', compliance: '日志溯源保存 6 个月。' }
            },
            {
                id: 'log', title: '🛡️ SIEM 态势感知', subTitle: 'Security Info & Event Mgt',
                tech: 'Splunk / ELK', desc: '全流量汇聚、告警关联分析与大屏指挥展现。',
                svgX: 600, svgY: 1100,
                details: { framework: 'Logstash / Kibana', protocol: 'TCP/UDP', assets: '攻击威胁情报', securityPolicy: '多维关联与告警', threatSurface: '日志被黑客清洗', hardening: '日志收集端配置 WORM 策略。', compliance: '等保集中审计要求。' }
            },
            {
                id: 'ci_cd', title: '🛠️ CI/CD 流水线', subTitle: 'DevSecOps Pipeline',
                tech: 'DevSecOps Pipeline', desc: '源码托管、自动构建打包与容器镜像仓库。',
                svgX: 835, svgY: 1100,
                details: { framework: 'GitLab / Docker', protocol: 'SSH / HTTPS', assets: '企业全量源码', securityPolicy: '上线前 AST 代码扫描', threatSurface: '.git 泄露、源码失窃', hardening: '外网严禁直接暴露 GitLab。', compliance: '安全研发生命周期 (SDL)。' }
            },
            {
                id: 'bastion', title: '堡垒机与跳板机', subTitle: 'Bastion Host',
                tech: 'Jumpserver', desc: '运维人员 SSH 登入核心服务器的唯一合法通道。',
                svgX: 1070, svgY: 1100,
                details: { framework: 'SSH / RDP Proxy', protocol: 'SSH 22', assets: '全网服务器密码', securityPolicy: '会话录屏录像与授权', threatSurface: '跳板机被拿下导致全网覆灭', hardening: '开启 2FA，并仅限内网专线可达。', compliance: '等保运维管控要求。' }
            }
        ];

        edges = [
            // Row 1 to Row 2
            { from: 'user', to: 'dns', key: 'user-dns', label: '1. 域名解析' },
            { from: 'user', to: 'ddos', key: 'user-ddos', label: '2. 流量引入' },
            { from: 'user', to: 'cdn', key: 'user-cdn', label: '3. 静态加速请求' },
            { from: 'user', to: 'lb', key: 'user-lb', label: '4. 直接动态请求 ➔' },
            { from: 'user', to: 'vpn', key: 'user-vpn', label: '办公网专线 ➔' },
            
            // Row 2 to Row 3
            { from: 'ddos', to: 'lb', key: 'ddos-lb', label: '清洗后回源 ➔' },
            { from: 'cdn', to: 'frontend', key: 'cdn-frontend', label: '缓存回源拉取 ➔' },
            
            // Row 3 to Row 4
            { from: 'lb', to: 'waf', key: 'lb-waf', label: '7层转发 ➔' },
            { from: 'waf', to: 'frontend', key: 'waf-frontend', label: '页面访问放行 ➔' },
            { from: 'waf', to: 'api_gw', key: 'waf-apigw', label: 'API接口请求 ➔' },
            { from: 'vpn', to: 'ms_admin', key: 'vpn-admin', label: '内网管理流量 ➔' },
            
            // Row 4 Internals and downward
            { from: 'frontend', to: 'api_gw', key: 'frontend-api', label: 'XHR/Fetch 异步 ➔' },
            { from: 'api_gw', to: 'auth', key: 'api-auth', label: '统一鉴权 ➔' },
            { from: 'api_gw', to: 'backend', key: 'api-backend', label: '路由转发至服务 ➔' },
            { from: 'auth', to: 'backend', key: 'auth-backend', label: '授权成功 ➔' },
            { from: 'task_sched', to: 'backend', key: 'task-backend', label: '定时触发执行 ➔' },
            { from: 'ci_cd', to: 'backend', key: 'cicd-backend', label: '容器部署下发 ➔' },
            { from: 'bastion', to: 'backend', key: 'bastion-backend', label: 'SSH 运维干预 ➔' },

            // Row 4 to Row 5 (Data Tier)
            { from: 'backend', to: 'cache', key: 'backend-cache', label: '频繁热点查询 ➔' },
            { from: 'backend', to: 'mq', key: 'backend-mq', label: '投递异步消息 ➔' },
            { from: 'backend', to: 'db', key: 'backend-db', label: '主库事务执行 ➔' },
            { from: 'ms_admin', to: 'db_read', key: 'admin-dbread', label: '统计报表导出 ➔' },

            // Row 5 to Row 6 (Storage and Logs)
            { from: 'mq', to: 'log', key: 'mq-log', label: '日志消费写入 ➔' },
            { from: 'mq', to: 'nosql', key: 'mq-nosql', label: '更新索引库 ➔' },
            { from: 'db', to: 'db_read', key: 'db-sync', label: 'Binlog 同步流 ➔' },
            { from: 'backend', to: 'oss', key: 'backend-oss', label: '业务附件存取 ➔' },
            
            // SIEM connects everywhere (logical link)
            { from: 'waf', to: 'log', key: 'waf-log', label: '告警流水 ➔' },
            { from: 'auth', to: 'log', key: 'auth-log', label: '审计日志 ➔' }
        ];
    }

    return { profileType, profileTitle, nodes, edges };
}

function getVulnerabilityAttackProcessLegacy(activeVuln) {
    if (!activeVuln) {
        return {
            title: '全站健康安全运转链路 (未检出已知漏洞)',
            steps: [
                { num: 1, tier: '🧑 终端用户', action: '合法 HTTPS 请求', desc: '浏览器发起正常业务访问' },
                { num: 2, tier: '⚡ CDN / 🛡️ WAF', action: '安全流量清洗', desc: 'Anycast 加速与 OWASP 规则过滤' },
                { num: 3, tier: '🔑 鉴权网关', action: '身份与权限校验', desc: 'OAuth 2.0 / JWT 有效性核验' },
                { num: 4, tier: '⚙️ 业务后端', action: '业务逻辑处理', desc: 'ORM 参数化执行与数据渲染' },
                { num: 5, tier: '🗄️ 核心数据库', action: '事务安全持久化', desc: '数据隔离持久化与加密落盘' }
            ]
        };
    }

    // 优先读取由后端深度分析生成的 4-Stage 漏洞渗透利用链 (Multi-Stage Exploit Chain)
    if (activeVuln.exploit_chain && activeVuln.exploit_chain.stages) {
        const chain = activeVuln.exploit_chain;
        return {
            title: `⚔️ ${chain.chain_name || activeVuln.title}`,
            steps: chain.stages.map(st => ({
                num: st.step,
                tier: st.badge || `Step ${st.step}: ${st.phase}`,
                action: st.action,
                desc: st.detail
            }))
        };
    }

    const t = (activeVuln.title || '') + ' ' + (activeVuln.category || '') + ' ' + (activeVuln.url || '');
    const tLower = t.toLowerCase();

    if (tLower.includes('sql') || tLower.includes('注入') || tLower.includes('backup.sql') || tLower.includes('.sql')) {
        return {
            title: '💥 数据库脱库与 SQL 注入利用全过程链路 (Database Dump / SQLi Exploitation Chain)',
            steps: [
                { num: 1, tier: '🧑 Step 1: 入口注入', action: '输入恶意 Payload / 探测备份', desc: `向 ${activeVuln.url} 发送恶意注入参数或直接请求备份路径` },
                { num: 2, tier: '🛡️ Step 2: 绕过阻断', action: '防护规则被绕过 / 放行', desc: '特制编码或缺失 /backup.sql 规则拦截，请求被直接放行' },
                { num: 3, tier: '⚙️ Step 3: 后端执行', action: '动态拼接 SQL / 文件未防护', desc: '后端未进行预编译参数绑定，直接执行拼接查询或读取文件' },
                { num: 4, tier: '🗄️ Step 4: 数据脱库', action: '提取全库数据与脱库', desc: '数据库无差别执行黑客指令，核心用户凭据与业务表完全失窃' }
            ]
        };
    } else if (tLower.includes('.env') || tLower.includes('配置') || tLower.includes('ak/sk') || tLower.includes('git')) {
        return {
            title: '💥 敏感配置暴露 ➔ 凭据提取 ➔ 数据库接管渗透链 (.env & Config Exposure Chain)',
            steps: [
                { num: 1, tier: '🧑 Step 1: 路径探测', action: '发起直接隐蔽路径探测', desc: `向 ${activeVuln.url} 发起 GET /.env 敏感配置文件请求` },
                { num: 2, tier: '⚡ Step 2: 边界突破', action: '缺少点号隐藏文件拦截', desc: 'Web 服务器未限制隐藏文件访问权限，返回 HTTP 200' },
                { num: 3, tier: '⚙️ Step 3: 凭据提取', action: '配置文件裸露明文读取', desc: 'Web 根目录下放置生产环境 .env，被黑客直接下载' },
                { num: 4, tier: '🗄️ Step 4: 权限接管', action: '提取数据库凭据与 Token 私钥', desc: '黑客提取 DATABASE_URL、云平台 AK/SK，完全接管底层数据库' }
            ]
        };
    } else if (tLower.includes('身份证') || tLower.includes('手机号') || tLower.includes('sensitive') || tLower.includes('隐私') || tLower.includes('api')) {
        return {
            title: '🚨 API 未授权 ➔ IDOR 越权遍历 ➔ 公民隐私脱裤链 (PII Data Leakage Chain)',
            steps: [
                { num: 1, tier: '🗄️ Step 1: 数据落盘', action: '敏感身份证明文存储', desc: '数据库中存储的公民 18 位身份证与手机号未实施哈希/密文加密' },
                { num: 2, tier: '⚙️ Step 2: 接口暴露', action: '接口全量取出敏感字段', desc: '后端 API 控制器在查询用户资料时，将隐私字段原值全量读出' },
                { num: 3, tier: '💻 Step 3: 前端回显', action: '前端未做脱敏掩码', desc: '前端页面未应用 330106****1234 算法掩码，直接在 DOM 树中渲染' },
                { num: 4, tier: '🧑 Step 4: 批量外泄', action: '明文窃取公民隐私', desc: '任何访问该页面的攻击者均可批量爬取真实个人身份证，违反《数据安全法》' }
            ]
        };
    } else if (tLower.includes('tamper') || tLower.includes('篡改') || tLower.includes('暗链') || tLower.includes('挂马') || tLower.includes('博彩') || tLower.includes('xss')) {
        return {
            title: '🚨 客户端脚本注入 ➔ 会话凭据劫持 ➔ 后台登录接管链 (Exploit Progression Chain)',
            steps: [
                { num: 1, tier: '⚙️ Step 1: 载荷植入', action: '页面模板被黑客非法篡改', desc: '攻击者通过后门或弱口令入侵服务器，修改了页面静态 HTML 源码' },
                { num: 2, tier: '💻 Step 2: 客户端执行', action: '植入隐藏跳转暗链 / 挖矿 JS', desc: '网页 DOM 结构中潜伏 display:none 赌博黑产外链或 CoinHive 脚本' },
                { num: 3, tier: '🛡️ Step 3: 策略突破', action: '出网防篡改基线校验缺失', desc: 'WAF 未能及时感知并阻断被篡改页面的非合规外链与违规关键词' },
                { num: 4, tier: '🧑 Step 4: 凭据劫持', action: '访客受害 / 算力被盗用', desc: '政企访客被误导至博彩网站遭遇网络诈骗，或客户端 CPU 算力被盗挖' }
            ]
        };
    } else {
        return {
            title: `🚨 ${activeVuln.title} 风险利用与影响过程链路`,
            steps: [
                { num: 1, tier: '🧑 Step 1: 客户端探测', action: '发起非安全配置探测', desc: `向 ${activeVuln.url} 发送探测验证包` },
                { num: 2, tier: '🛡️ Step 2: 网关策略缺失', action: '安全防护策略缺失', desc: '网关未配置严格的 HTTP 安全头或越权拦截策略' },
                { num: 3, tier: '⚙️ Step 3: 服务端暴露', action: '业务逻辑暴露安全隐患', desc: '后端未进行合规安全加固与敏感异常过滤' },
                { num: 4, tier: '🌐 Step 4: 影响扩散', action: '引发数据泄露或中间人劫持', desc: '攻击者利用该配置缺陷实施进一步的权限提升或中间人监听' }
            ]
        };
    }
}

// 证据型风险流程：只展示已观测请求、证据、影响研判与复测步骤，不把推测渲染成已发生的攻击。
function getVulnerabilityAttackProcess(activeVuln) {
    if (!activeVuln) {
        return {
            title: '巡检证据与安全边界链路（当前无风险发现）',
            steps: [
                { num: 1, tier: '🧑 访问端', action: '发起授权巡检请求', desc: '请求仅来自任务配置的授权域名与范围。' },
                { num: 2, tier: '🌐 目标站点', action: '保存页面与响应证据', desc: '记录可达页面、资源和安全响应特征。' },
                { num: 3, tier: '🔍 检测规则', action: '执行当前启用规则', desc: '按任务策略检查漏洞、篡改和敏感信息。' },
                { num: 4, tier: '📄 报告闭环', action: '生成基线与复测入口', desc: '结果可追踪、可复测，不代表对未覆盖风险作保证。' }
            ]
        };
    }
    const verified = activeVuln.verified === 1 || activeVuln.verified === true;
    const evidenceState = verified ? '已取得响应证据' : '证据不足，待复核';
    const target = activeVuln.url || '当前任务目标';
    return {
        title: `风险证据链：${activeVuln.title || '未命名发现'}（${evidenceState}）`,
        steps: [
            { num: 1, tier: '🧑 Step 1: 授权请求', action: '发送受限探测请求', desc: `目标：${target}` },
            { num: 2, tier: '🌐 Step 2: 响应观测', action: '保存状态、头部与内容片段', desc: '只使用任务中实际取得的响应证据。' },
            { num: 3, tier: '🔍 Step 3: 风险研判', action: verified ? '证据支持当前风险判断' : '保留为疑似风险并提示人工复核', desc: '影响范围是基于当前证据的研判，不等同于已完成攻击。' },
            { num: 4, tier: '🛠️ Step 4: 整改复测', action: '给出修复建议并支持复测', desc: '修复后使用同一风险记录复测，失败时不自动判定为已修复。' }
        ]
    };
}

function getNodeAttackBehaviorLegacy(nodeId, activeVuln) {
    if (!activeVuln) {
        return {
            status: 'safe',
            role: '🟢 正常运转',
            text: '未检出已知安全隐患，运行基线合规。'
        };
    }

    const t = ((activeVuln.title || '') + ' ' + (activeVuln.category || '') + ' ' + (activeVuln.url || '')).toLowerCase();

    // 1. SQL 注入 / 数据库脱库 / 备份文件暴露
    if (t.includes('sql') || t.includes('注入') || t.includes('backup.sql') || t.includes('.sql') || t.includes('db_config')) {
        switch (nodeId) {
            case 'user':
                return { status: 'affected', role: '🔴 攻击发起端', text: '向前端输入恶意 SQL Payload (\' OR 1=1 --) 或探测 /backup.sql 备份' };
            case 'cdn':
            case 'edge_cdn':
                return { status: 'safe', role: '⚪ 边缘透传', text: '动态 SQL 探测请求直接透传回源' };
            case 'frontend':
            case 'frontend_ssr':
                return { status: 'affected', role: '🔴 敏感数据回显', text: '接收后端返回的脱库数据并在前端页面 DOM 中回显呈现' };
            case 'waf':
                return { status: 'affected', role: '🔴 防火墙被绕过', text: '特制编码绕过或缺少备份路径拦截规则，放行恶意请求' };
            case 'auth':
            case 'auth_iam':
                return { status: 'affected', role: '🚨 权限与鉴权失效', text: '管理员凭证与权限表随数据库失窃，黑客绕过登录验证' };
            case 'backend':
            case 'serverless_func':
                return { status: 'root', role: '💥 漏洞源头 (未做预编译)', text: '后端未进行 SQL 参数化绑定，直接动态拼接并执行恶意查询' };
            case 'cache':
                return { status: 'affected', role: '🚨 缓存击穿与脏读', text: '数据库异常波动引发缓存击穿与脏数据读写' };
            case 'oss':
            case 'blob_storage':
                return { status: 'safe', role: '🟢 未受波及', text: '对象存储未涉及本次 SQL 注入直接利用' };
            case 'db':
            case 'cloud_db':
                return { status: 'affected', role: '💥 核心数据库脱库', text: '数据库无差别执行黑客指令，核心用户凭据与全库数据失窃' };
            case 'mq':
                return { status: 'safe', role: '🟢 未受波及', text: '异步消息队列调度正常运行' };
        }
    }

    // 2. 配置文件与敏感秘钥泄露 (.env / git / ak_sk)
    if (t.includes('.env') || t.includes('配置') || t.includes('ak/sk') || t.includes('git') || t.includes('svn')) {
        switch (nodeId) {
            case 'user':
                return { status: 'affected', role: '🔴 攻击探测端', text: '发起直接探测 GET /.env 或 /.git 隐蔽配置文件' };
            case 'cdn':
            case 'edge_cdn':
                return { status: 'affected', role: '⚪ 边缘未过滤', text: '未对隐藏点号文件设置 403 阻断策略' };
            case 'frontend':
            case 'frontend_ssr':
                return { status: 'safe', role: '🟢 未受波及', text: '前端页面未直接包含服务端私密配置' };
            case 'waf':
                return { status: 'affected', role: '🔴 防护规则缺失', text: 'Web 网关未拦截点号隐蔽文件访问 (HTTP 200 放行)' };
            case 'auth':
            case 'auth_iam':
                return { status: 'affected', role: '🚨 鉴权密钥失窃', text: 'JWT 签名私钥与 API 秘钥明文泄露，鉴权完全失效' };
            case 'backend':
            case 'serverless_func':
                return { status: 'root', role: '💥 漏洞源头 (敏感文件裸露)', text: 'Web 根目录下放置生产环境 .env 配置文件，被黑客直接下载' };
            case 'cache':
                return { status: 'affected', role: '🚨 凭据外泄', text: 'Redis 认证密码在 .env 中明文曝光' };
            case 'oss':
            case 'blob_storage':
                return { status: 'affected', role: '🚨 AK/SK 私钥外泄', text: '云平台 AccessKey/SecretKey 泄露，存储桶面临失陷' };
            case 'db':
            case 'cloud_db':
                return { status: 'affected', role: '💥 数据库接管', text: 'DATABASE_URL 明文暴露，黑客获取数据库账号密码直连' };
            case 'mq':
                return { status: 'affected', role: '🚨 MQ 凭据外泄', text: '消息中间件账号密码在配置文件中明文泄露' };
        }
    }

    // 3. 公民个人身份证明文泄露 (身份证 / 手机号 / PII)
    if (t.includes('身份证') || t.includes('手机号') || t.includes('sensitive') || t.includes('隐私')) {
        switch (nodeId) {
            case 'user':
                return { status: 'affected', role: '🔴 个人隐私受害', text: '任何外部访客与爬虫均可批量读取公民 18 位真实身份证号' };
            case 'cdn':
            case 'edge_cdn':
                return { status: 'safe', role: '⚪ 静态加速透传', text: '透传包含未脱敏隐私数据的 HTML/JSON 报文' };
            case 'frontend':
            case 'frontend_ssr':
                return { status: 'root', role: '💥 漏洞源头 (未做脱敏掩码)', text: '前端页面未应用 330106****1234 掩码算法，直接在 DOM 树明文渲染' };
            case 'waf':
                return { status: 'safe', role: '⚪ 业务语义盲区', text: 'WAF 无法识别业务层公民身份证明文出网' };
            case 'auth':
            case 'auth_iam':
                return { status: 'affected', role: '🚨 越权鉴权缺陷', text: '未对用户隐私查询接口设置最小化权限校验 (IDOR 越权)' };
            case 'backend':
            case 'serverless_func':
                return { status: 'affected', role: '🔴 全量明文查询', text: '后端 API 查询用户资料时未实施脱敏，将身份证原值全量取出' };
            case 'cache':
                return { status: 'affected', role: '🔴 明文缓存数据', text: 'Redis 缓存池中存有未加密的公民个人身份证明文' };
            case 'oss':
            case 'blob_storage':
                return { status: 'safe', role: '🟢 未受波及', text: '对象存储未涉及明文流出' };
            case 'db':
            case 'cloud_db':
                return { status: 'affected', role: '🔴 明文数据落盘', text: '数据库中公民身份证未经加密/散列，处于裸露明文存储状态' };
            case 'mq':
                return { status: 'safe', role: '🟢 未受波及', text: '消息调度正常运行' };
        }
    }

    // 4. 页面篡改与暗链挂马
    if (t.includes('tamper') || t.includes('篡改') || t.includes('暗链') || t.includes('挂马') || t.includes('博彩') || t.includes('挖矿')) {
        switch (nodeId) {
            case 'user':
                return { status: 'affected', role: '🔴 受害政企访客', text: '访客被恶意重定向至博彩欺诈网站，或客户端 CPU 算力被盗挖' };
            case 'cdn':
            case 'edge_cdn':
                return { status: 'affected', role: '⚪ 污染缓存分发', text: '边缘节点缓存了被篡改的恶意页面并加速扩散' };
            case 'frontend':
            case 'frontend_ssr':
                return { status: 'root', role: '💥 漏洞源头 (植入暗链/脚本)', text: 'DOM 树中潜伏 display:none 赌博黑产暗链或 CoinHive 挖矿 JS' };
            case 'waf':
                return { status: 'affected', role: '🔴 出网校验缺失', text: 'WAF 未配置网页防篡改基线核验与违规外链拦截规则' };
            case 'auth':
            case 'auth_iam':
                return { status: 'affected', role: '🚨 后台权限失守', text: '管理员口令可能被盗用，导致静态页面发布权限被黑客劫持' };
            case 'backend':
            case 'serverless_func':
                return { status: 'affected', role: '🔴 静态模板污染', text: '后端服务器上的静态 HTML 模板文件已被黑客非法修改' };
            case 'cache':
                return { status: 'safe', role: '⚪ 缓存污染', text: '缓存池中存有被篡改页面片段' };
            case 'oss':
            case 'blob_storage':
                return { status: 'safe', role: '🟢 未受波及', text: '对象存储未受损' };
            case 'db':
            case 'cloud_db':
                return { status: 'safe', role: '🟢 未受波及', text: '数据库持久表结构完好' };
            case 'mq':
                return { status: 'safe', role: '🟢 未受波及', text: '消息队列正常运行' };
        }
    }

    // 5. 默认通用安全风险
    switch (nodeId) {
        case 'user':
            return { status: 'affected', role: '🔴 客户端风险', text: '通信存在被中间人监听劫持或伪造请求风险' };
        case 'cdn':
        case 'edge_cdn':
            return { status: 'safe', role: '⚪ 流量透传', text: '正常转发流量' };
        case 'frontend':
        case 'frontend_ssr':
            return { status: 'affected', role: '🔴 前端呈现', text: '未配置严格的内容安全策略 (CSP)' };
        case 'waf':
            return { status: 'root', role: '💥 漏洞源头 (策略缺失)', text: '网关未配置严格的 HSTS / CORS / 安全响应头防护' };
        case 'auth':
        case 'auth_iam':
            return { status: 'affected', role: '🚨 访问控制', text: '鉴权边界策略需进一步加固' };
        case 'backend':
        case 'serverless_func':
            return { status: 'affected', role: '🔴 业务逻辑', text: '后端服务未启用传输层强制加密校验' };
        case 'cache':
            return { status: 'safe', role: '🟢 正常运行', text: '缓存运行正常' };
        case 'oss':
        case 'blob_storage':
            return { status: 'safe', role: '🟢 正常运行', text: '存储服务正常' };
        case 'db':
        case 'cloud_db':
            return { status: 'safe', role: '🟢 正常运行', text: '数据库正常' };
        case 'mq':
            return { status: 'safe', role: '🟢 正常运行', text: '消息调度正常' };
    }
    return { status: 'safe', role: '🟢 正常运转', text: '运行正常' };
}

window.toggleTopologyNodeDetail = function(nodeId) {
    if (selectedTopologyNodeId === nodeId) {
        selectedTopologyNodeId = null;
    } else {
        selectedTopologyNodeId = nodeId;
    }
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

window.switchBurpSubTab = function(subTab) {
    currentBurpSubTab = subTab;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

window.selectFinding = function(idx) {
    selectedFindingIndex = idx;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

window.switchHttpViewTab = function(tabName) {
    currentHttpViewTab = tabName;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

window.jumpToTopologyWithFinding = function(findingIndex) {
    currentBurpSubTab = 'sitemap';
    selectedTopologyFindingIndex = findingIndex;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
        setTimeout(() => {
            const el = document.getElementById('topology-canvas-section') || document.querySelector('.topo-layout-container') || document.querySelector('.attack-process-card');
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }, 100);
    }
};

window.selectTopologyVuln = function(idx) {
    selectedTopologyFindingIndex = idx;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
        setTimeout(() => {
            const el = document.querySelector('.attack-process-card') || document.querySelector('.topo-layout-container');
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }, 50);
    }
};

window.changeTopologyHeight = function(heightPx) {
    topologyCanvasHeight = heightPx;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

window.openTopologyInNewTab = function() {
    if (currentDetailTaskId) {
        window.open(`/api/v1/tasks/${currentDetailTaskId}/topology-fullscreen`, '_blank');
    }
};

window.clearFocusPage = function() {
    focusPageUrl = null;
    if (currentTaskDetailData) {
        renderBurpScannerLayout(currentTaskDetailData);
    }
};

function renderBurpScannerLayout(data) {
    currentTaskDetailData = data;
    const container = document.getElementById('main-content');
    if (!container) return;

    const task = data.task;
    const allFindings = data.findings || [];
    
    // 如果设置了单页面聚焦查看，过滤只展示该 URL 的漏洞
    let displayFindings = allFindings;
    if (focusPageUrl) {
        const filtered = allFindings.filter(f => f.url === focusPageUrl || f.url.startsWith(focusPageUrl));
        if (filtered.length > 0) {
            displayFindings = filtered;
        }
    }

    const sitemap = data.sitemap || [];
    const logs = data.audit_logs || [];
    const architecture = getArchitectureData(task, sitemap, displayFindings, data.architecture);
    const summary = task.summary || {};
    const score = summary.security_score !== undefined ? summary.security_score : '--';
    const scoreColor = typeof score === 'number' ? (score < 60 ? '#dc2626' : (score < 85 ? '#d97706' : '#16a34a')) : '#64748b';
    
    const currentFinding = displayFindings[selectedFindingIndex] || displayFindings[0] || null;

    let focusBannerHtml = '';
    if (focusPageUrl) {
        focusBannerHtml = `
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-radius:8px; padding:10px 14px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:8px; font-size:13px; color:#1e40af;">
                <span style="font-size:16px;">🎯</span>
                <div>
                    <strong>当前正聚焦查看单页面拓扑与漏洞：</strong> <code style="background:#dbeafe; color:#1e3a8a; padding:2px 6px; border-radius:4px;">${escapeHtml(focusPageUrl)}</code> (共 ${displayFindings.length} 处漏洞)
                </div>
            </div>
            <button class="btn btn-primary" style="font-size:11px; padding:3px 10px;" onclick="clearFocusPage()">🔄 返回查看整站全部漏洞 (${allFindings.length})</button>
        </div>
        `;
    }

    let html = `
    <div class="burp-container">
        <!-- 顶部导航卡片 -->
        <div class="burp-header-card">
            <div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <button class="btn" style="padding:4px 10px; font-size:12px;" onclick="currentDetailTaskId=null; renderTabContent('tasks')">← 返回任务列表</button>
                    <h3 style="font-size:16px; color:#0f172a; margin:0;">${escapeHtml(task.name)}</h3>
                    <span class="tag ${task.status === 'COMPLETED' ? 'tag-low' : (task.status === 'RUNNING' ? 'tag-medium' : 'tag-info')}">${task.status === 'COMPLETED' ? '已完成' : escapeHtml(task.status)}</span>
                </div>
                <div style="display:flex; gap:16px; font-size:12px; color:#64748b; margin-top:8px; align-items:center; flex-wrap:wrap;">
                    <span>📍 目标网站: <code style="color:#0284c7;">${escapeHtml(task.target_url)}</code></span>
                    <span>🕒 时间: ${escapeHtml((task.created_at || '').substring(0, 19).replace('T', ' '))}</span>
                    <span>🛡️ 安全健康分: <strong style="color:${scoreColor}">${escapeHtml(score)} 分</strong></span>
                    <span>🐞 检出问题: <strong>${displayFindings.length}</strong> 项 ${focusPageUrl ? '(单页聚焦)' : ''}</span>
                    <span>🌐 探测页面: <strong>${sitemap.length}</strong> 个节点</span>
                </div>
                <div style="width:300px; margin-top:6px;">
                    <div class="progress-bar"><div class="progress-val" style="width:${task.progress}%"></div></div>
                    <div style="font-size:11px; color:#64748b; margin-top:2px;">${escapeHtml(task.current_stage || '')} (${escapeHtml(task.progress)}%)</div>
                </div>
            </div>

            <div style="display:flex; gap:8px;">
                <button class="btn btn-primary" onclick="retestAllTask(${safeInlineArg(task.id)})">⚡ 一键整站重新探测与复测</button>
                <button class="btn" onclick="window.open(${safeInlineArg(`/api/v1/reports/${task.id}/html`)})">📄 查看浅色评估报告</button>
            </div>
        </div>

        ${focusBannerHtml}

        <!-- Burp Scanner 视图主导航选项卡 -->
        <div class="burp-nav-tabs">
            <button class="burp-tab-btn ${currentBurpSubTab === 'sitemap' ? 'active' : ''}" onclick="switchBurpSubTab('sitemap')">🏛️ 网站架构与拓扑实例图 (连线与漏洞标红)</button>
            <button class="burp-tab-btn ${currentBurpSubTab === 'issues' ? 'active' : ''}" onclick="switchBurpSubTab('issues')">🐞 查出的安全隐患清单 (${displayFindings.length})</button>
            <button class="burp-tab-btn ${currentBurpSubTab === 'logger' ? 'active' : ''}" onclick="switchBurpSubTab('logger')">📜 发送的探测记录与报文 (${logs.length})</button>
        </div>

        <!-- 内容区域 -->
        <div id="burp-subtab-content">
            ${renderBurpSubTabContent(displayFindings, currentFinding, sitemap, logs, architecture, task)}
        </div>
    </div>
    `;
    
    container.innerHTML = html;
}

function renderBurpSubTabContent(findings, currentFinding, sitemap, logs, architecture, task) {
    if (currentBurpSubTab === 'issues') {
        if (!findings || findings.length === 0) {
            return `
            <div class="card" style="padding:40px; text-align:center;">
                <div style="font-size:40px; margin-bottom:10px;">🎉</div>
                <h3 style="color:#16a34a; font-size:18px;">当前启用检测项未返回安全发现</h3>
                <p style="color:#64748b; font-size:13px; margin-top:4px;">该结论仅覆盖本次授权范围、已执行规则和可达页面，不代表目标不存在其他风险。</p>
            </div>`;
        }

        let issuesListHtml = '';
        findings.forEach((f, idx) => {
            const isSelected = idx === selectedFindingIndex ? 'active' : '';
            const sevClass = f.severity.toLowerCase();
            const titleLower = (f.title || '').toLowerCase();
            const isSrcExploitable = f.src_type === 'SRC_EXPLOITABLE' || [
                'sql', '注入', 'sqli', 'ssti', '模板', '命令注入', 'command', 'rce', '代码执行',
                '文件读取', '路径穿越', 'lfi', 'path traversal', 'bola', 'idor', '越权', '未授权',
                'xss', '跨站脚本', 'ssrf', '请求伪造', '挖矿', '后门', '暗链', '篡改', '涂鸦', 'defacement',
                'coinhive', 'eval(', '.env', 'backup.sql', '.git', '身份证', '银行卡', 'accesskey',
                '数据库连接串', 'jwt', 'cors', '跨域'
            ].some(k => titleLower.includes(k));

            issuesListHtml += `
            <div class="burp-issue-item ${isSelected}" onclick="selectFinding(${idx})">
                <div class="burp-issue-title">
                    <span class="tag tag-${escapeHtml(sevClass)}" style="font-size:10px; padding:1px 5px;">${escapeHtml(f.severity)}</span>
                    <span class="tag tag-${isSrcExploitable ? 'critical' : 'info'}" style="font-size:9px; padding:0 4px;">${isSrcExploitable ? '🎯 SRC' : '📋 基线'}</span>
                    <span style="font-size:12px; font-weight:600; color:#0f172a; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(f.title)}</span>
                </div>
                <div class="burp-issue-meta">
                    <span>${escapeHtml(f.url)}</span>
                    <span class="tag ${f.status === 'OPEN' ? 'tag-high' : 'tag-low'}" style="font-size:9px; padding:0 4px;">${f.status === 'OPEN' ? '待处理' : escapeHtml(f.status)}</span>
                </div>
            </div>
            `;
        });

        let httpContent = '';
        if (currentFinding) {
            if (currentHttpViewTab === 'request') {
                httpContent = currentFinding.raw_request || `GET / HTTP/1.1\r\nHost: ${task.target_url}\r\nUser-Agent: DAS-SentinelAgent/1.0\r\nAccept: */*\r\n`;
            } else if (currentHttpViewTab === 'response') {
                httpContent = currentFinding.raw_response || '[未保存原始 HTTP 响应]';
            } else {
                httpContent = JSON.stringify(currentFinding.evidence || {}, null, 2);
            }
        }

        const currentTitleLower = (currentFinding?.title || '').toLowerCase();
        const isCurrentSrc = currentFinding && (currentFinding.src_type === 'SRC_EXPLOITABLE' || [
            'sql', '注入', 'sqli', 'ssti', '模板', '命令注入', 'command', 'rce', '代码执行',
            '文件读取', '路径穿越', 'lfi', 'path traversal', 'bola', 'idor', '越权', '未授权',
            'xss', '跨站脚本', 'ssrf', '请求伪造', '挖矿', '后门', '暗链', '篡改', '涂鸦', 'defacement',
            'coinhive', 'eval(', '.env', 'backup.sql', '.git', '身份证', '银行卡', 'accesskey',
            '数据库连接串', 'jwt', 'cors', '跨域'
        ].some(k => currentTitleLower.includes(k)));

        return `
        <div class="burp-layout-two-column">
            <div class="burp-issues-sidebar">${issuesListHtml}</div>
            <div class="burp-details-viewer">
                <div class="burp-advisory-card">
                    ${currentFinding ? `
                        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                            <div>
                                <span class="tag tag-${escapeHtml(currentFinding.severity.toLowerCase())}">${escapeHtml(currentFinding.severity)}</span>
                                <span class="tag tag-${isCurrentSrc ? 'critical' : 'info'}" style="font-size:11px; padding:2px 7px; margin-left:4px;">${isCurrentSrc ? '🎯 行业 SRC 实战收录漏洞' : '📋 安全配置基线建议 (SRC 忽略项)'}</span>
                                <span style="font-size:15px; font-weight:700; margin-left:6px;">${escapeHtml(currentFinding.title)}</span>
                            </div>
                            <div style="display:flex; gap:6px;">
                                <button class="btn" style="background:#f0f9ff; color:#0284c7; border-color:#bae6fd; font-size:11px; padding:3px 10px;" onclick="window.jumpToTopologyWithFinding(${selectedFindingIndex})">🏛️ 在拓扑图中定位风险来源</button>
                                <button class="btn btn-primary" style="font-size:11px; padding:3px 10px;" onclick="retestSingleFindingLive(${safeInlineArg(currentFinding.id)})">⚡ 一键复测</button>
                            </div>
                        </div>
                        <p style="font-size:12px; color:#475569; margin-top:8px; line-height:1.5;">${escapeHtml(currentFinding.impact || '该漏洞可能造成未经授权的信息泄露或业务风险。')}</p>
                        <div style="margin-top:4px; font-size:12px; color:#0284c7;"><strong>URL:</strong> <code>${escapeHtml(currentFinding.url || '')}</code></div>
                        ${currentFinding.remediation ? `<div style="margin-top:4px; font-size:12px; color:#16a34a;"><strong>🛠️ 加固建议:</strong> ${escapeHtml(currentFinding.remediation)}</div>` : ''}
                    ` : '请在左侧列表中选择一个安全问题以查看详情与通信报文'}
                </div>
                <div class="burp-http-card" style="margin-top:10px; background:#fff; border:1px solid #e2e8f0; border-radius:8px; overflow:hidden;">
                    <div class="burp-http-tabs" style="display:flex; background:#f8fafc; border-bottom:1px solid #e2e8f0; padding:6px 10px; gap:8px;">
                        <button class="btn ${currentHttpViewTab === 'request' ? 'btn-primary' : ''}" style="font-size:11px; padding:3px 10px;" onclick="window.switchHttpViewTab('request')">Request (发出的测试报文)</button>
                        <button class="btn ${currentHttpViewTab === 'response' ? 'btn-primary' : ''}" style="font-size:11px; padding:3px 10px;" onclick="window.switchHttpViewTab('response')">Response (服务器响应)</button>
                        <button class="btn ${currentHttpViewTab === 'evidence' ? 'btn-primary' : ''}" style="font-size:11px; padding:3px 10px;" onclick="window.switchHttpViewTab('evidence')">Evidence (漏洞证据细节)</button>
                    </div>
                    <pre style="font-size:11px; padding:12px; margin:0; background:#f8fafc; font-family:monospace; color:#0f172a; max-height:380px; overflow:auto; white-space:pre-wrap; word-break:break-all;">${escapeHtml(httpContent)}</pre>
                </div>
            </div>
        </div>
        `;

    } else if (currentBurpSubTab === 'sitemap') {
        // 1. 根据后端保存的响应指纹生成观测拓扑；不按域名猜测内部组件。
        const siteTopo = generateObservedTopology(task, sitemap, findings, architecture);
        const nodes = siteTopo.nodes;
        const edges = siteTopo.edges;

        // 🎯 动态定位当前拓扑中的具体节点 ID (自适应 Vercel/Next.js 与传统政企多架构)
        const fNode = nodes.find(n => n.id.includes('frontend'))?.id || 'frontend';
        const bNode = nodes.find(n => n.id.includes('backend') || n.id.includes('func') || n.id.includes('serverless'))?.id || 'backend';
        const dNode = nodes.find(n => n.id.includes('db'))?.id || 'db';
        const aNode = nodes.find(n => n.id.includes('auth'))?.id || 'auth';
        const wNode = nodes.find(n => n.id.includes('waf') || n.id.includes('cdn'))?.id || 'cdn';
        const cNode = nodes.find(n => n.id.includes('cache'))?.id || bNode;
        const sNode = nodes.find(n => n.id.includes('oss') || n.id.includes('storage') || n.id.includes('blob'))?.id || 'oss';

        let activeVuln = null;
        let rootCauseNodeId = '';
        let affectedNodeIds = new Set();
        let affectedEdges = new Set();
        let impactAnalysisText = '';

        // 分流：实战高危漏洞与专项利用链 vs 基础安全配置标头建议
        const allFindingsList = findings || [];
        const highImpactFindings = allFindingsList.filter(f => {
            const sev = (f.severity || '').toUpperCase();
            const cat = f.category || '';
            const t = (f.title || '').toLowerCase();
            return sev === 'CRITICAL' || sev === 'HIGH' || sev === 'MEDIUM' || cat === 'SENSITIVE' || cat === 'TAMPER' || t.includes('sql') || t.includes('xss') || t.includes('api') || t.includes('cors') || t.includes('git') || t.includes('.env') || t.includes('backup') || t.includes('ssti') || t.includes('bola') || t.includes('idor');
        });
        const complianceHeaders = allFindingsList.filter(f => !highImpactFindings.includes(f));

        // 默认优先研判实战高危漏洞，若无高危漏洞则展示合规项
        const displayFindings = highImpactFindings.length > 0 ? highImpactFindings : allFindingsList;

        if (displayFindings.length > 0) {
            const vIdx = Math.min(selectedTopologyFindingIndex, displayFindings.length - 1);
            activeVuln = displayFindings[vIdx];
            const title = (activeVuln.title || '').toLowerCase();
            const url = (activeVuln.url || '').toLowerCase();
            const cat = activeVuln.category || '';

            if (url.includes('.env') || title.includes('环境') || title.includes('密钥') || title.includes('ak/sk') || title.includes('lfi') || title.includes('文件读取')) {
                rootCauseNodeId = bNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(aNode); affectedNodeIds.add(bNode); affectedNodeIds.add(dNode);
                impactAnalysisText = '💥 漏洞源头在【后端业务逻辑/云函数】，暴露了敏感系统文件与核心凭据，链路已被全线击穿！';
            } else if (url.includes('.git') || url.includes('.svn')) {
                rootCauseNodeId = fNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(aNode); affectedNodeIds.add(bNode);
                impactAnalysisText = '💥 漏洞源头在【网页前端】，由于版本控制源码目录暴露，黑客可下载全部前后端源代码。';
            } else if (url.includes('backup.sql') || title.includes('数据库') || url.includes('db_config') || title.includes('sql')) {
                rootCauseNodeId = dNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(aNode); affectedNodeIds.add(bNode); affectedNodeIds.add(dNode);
                impactAnalysisText = '💥 漏洞源头在【核心数据库】，由于 SQL 注入或备份暴露，整库面临脱裤风险！';
            } else if (cat === 'SENSITIVE' || title.includes('身份证') || title.includes('手机号') || title.includes('api') || title.includes('bola') || title.includes('idor') || title.includes('越权')) {
                rootCauseNodeId = aNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(aNode); affectedNodeIds.add(bNode); affectedNodeIds.add(dNode);
                impactAnalysisText = '💥 漏洞源头在【认证网关与接口】，API 未授权或 BOLA 越权导致敏感隐私在全链路扩散！';
            } else if (cat === 'TAMPER' || title.includes('暗链') || title.includes('篡改') || title.includes('xss') || title.includes('csp')) {
                rootCauseNodeId = fNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(wNode);
                impactAnalysisText = '💥 漏洞源头在【前端呈现层】，存在 XSS 脚本注入或暗链挂马，WAF 未能有效阻断。';
            } else if (title.includes('ssti') || title.includes('命令注入') || title.includes('rce')) {
                rootCauseNodeId = bNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(aNode); affectedNodeIds.add(bNode); affectedNodeIds.add(dNode);
                impactAnalysisText = '💥 漏洞源头在【业务后端应用】，模板注入 / 命令执行导致服务器宿主机被完全接管！';
            } else {
                rootCauseNodeId = fNode;
                affectedNodeIds.add('user'); affectedNodeIds.add(fNode); affectedNodeIds.add(wNode); affectedNodeIds.add(bNode);
                impactAnalysisText = '⚠️ 安全基线配置提示：存在响应标头或传输层弱配置项。';
            }

            // 统一将影响描述限定为当前观测和研判，避免把潜在影响渲染为已经完成的攻击。
            const evidenceState = activeVuln.verified === 1 || activeVuln.verified === true
                ? '已取得响应证据'
                : '证据不足，待人工复核';
            impactAnalysisText = `${evidenceState}：${activeVuln.impact || '当前发现可能带来安全风险，请结合证据详情评估影响范围。'}（不代表已完成攻击或数据已被获取）`;

            // 🎯 自动将受到波及的相邻节点间的所有连线标记为红色攻击渗透链路 (保证全链路端到端完全贯通连线)
            edges.forEach(e => {
                if (affectedNodeIds.has(e.from) && affectedNodeIds.has(e.to)) {
                    affectedEdges.add(e.key);
                }
            });

        }

        const attackFlow = getVulnerabilityAttackProcess(activeVuln);
        let attackStepsHtml = '';
        attackFlow.steps.forEach((st, sIdx) => {
            attackStepsHtml += `
            <div class="attack-step-node">
                <div class="attack-step-header">
                    <span class="attack-step-num">Step ${escapeHtml(st.num)}</span>
                    <span class="attack-step-tier">${escapeHtml(st.tier)}</span>
                </div>
                <div class="attack-step-action">${escapeHtml(st.action)}</div>
                <div class="attack-step-desc">${escapeHtml(st.desc)}</div>
            </div>
            `;
            if (sIdx < attackFlow.steps.length - 1) {
                attackStepsHtml += `<div class="attack-step-arrow">➔</div>`;
            }
        });

        // 3. 生成 SVG 连线 HTML (每 3 个矩形虚线输出一个箭头，并保留图三中的精致小字标签)
        let svgLinesHtml = `
        <defs>
            <!-- 默认正常流向箭头 (浅灰色) -->
            <marker id="topo-arrow-default" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />
            </marker>
            <!-- 🚨 漏洞攻击与渗透扩散流向箭头 (高亮红脉冲) -->
            <marker id="topo-arrow-danger" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="#dc2626" />
            </marker>
        </defs>
        `;

        const yRatio = topologyCanvasHeight / 1200;

        edges.forEach((e, eIdx) => {
            const nFrom = nodes.find(n => n.id === e.from);
            const nTo = nodes.find(n => n.id === e.to);
            if (!nFrom || !nTo) return;

            const isAffected = affectedEdges.has(e.key) || 
                               affectedEdges.has(`${e.from}-${e.to}`) || 
                               affectedEdges.has(`${e.to}-${e.from}`) ||
                               (affectedNodeIds.has(e.from) && affectedNodeIds.has(e.to));

            const strokeColor = isAffected ? '#dc2626' : '#94a3b8';
            const strokeWidth = isAffected ? '3.0' : '1.5';
            const dashArray = isAffected ? '7,3.5' : '5,3.5';
            const lineClass = isAffected ? 'affected-pulse-line' : 'normal-pulse-line';
            const markerEnd = isAffected ? 'url(#topo-arrow-danger)' : 'url(#topo-arrow-default)';

            const x1 = nFrom.svgX;
            const y1 = Math.round(nFrom.svgY * yRatio);
            const x2 = nTo.svgX;
            const y2 = Math.round(nTo.svgY * yRatio);
            const midX = (x1 + x2) / 2;
            const midY = (y1 + y2) / 2;

            const len = Math.hypot(x2 - x1, y2 - y1);
            const durSeconds = 3.0; // 舒适平稳的正常流动速度

            // 🎯 动态沿虚线流动的箭头 (按间距动态持续向前流动)
            let movingArrowsHtml = '';
            const numArrows = Math.max(2, Math.floor(len / 90));
            for (let i = 0; i < numArrows; i++) {
                const beginTime = ((i * (durSeconds / numArrows))).toFixed(2) + 's';
                movingArrowsHtml += `
                <polygon points="-5,-3.5 5,0 -5,3.5" fill="${strokeColor}" opacity="${isAffected ? '1.0' : '0.85'}">
                    <animateMotion path="M ${x1} ${y1} L ${x2} ${y2}" dur="${durSeconds}s" begin="${beginTime}" repeatCount="indefinite" rotate="auto" />
                </polygon>
                `;
            }

            // 🏷️ 拓扑图原本的小字
            const labelText = isAffected ? `⚠️ ${e.label || '渗透链路'}` : e.label;
            const labelW = Math.max(68, (labelText.length * 9.5) + 14);

            svgLinesHtml += `
            <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" 
                  stroke="${strokeColor}" stroke-width="${strokeWidth}" stroke-dasharray="${dashArray}" 
                  class="${lineClass}" marker-end="${markerEnd}" />
            ${movingArrowsHtml}
            <g transform="translate(${midX}, ${midY})">
                ${isAffected ? `
                    <rect x="${-labelW/2}" y="-10" width="${labelW}" height="20" rx="4" fill="#fee2e2" stroke="#dc2626" stroke-width="1.2" />
                    <text x="0" y="3.8" text-anchor="middle" font-size="10.5" font-weight="700" fill="#dc2626">${escapeHtml(labelText)}</text>
                ` : `
                    <rect x="${-labelW/2}" y="-9" width="${labelW}" height="18" rx="3" fill="#ffffff" fill-opacity="0.96" stroke="#cbd5e1" stroke-width="0.8" />
                    <text x="0" y="3.5" text-anchor="middle" font-size="10" font-weight="500" fill="#475569">${escapeHtml(labelText)}</text>
                `}
            </g>
            `;
        });


        // 4. 生成各个自适应 HTML 节点
        let nodesHtml = '';
        nodes.forEach(n => {
            const isRoot = n.id === rootCauseNodeId || (rootCauseNodeId.includes('db') && n.id.includes('db')) || (rootCauseNodeId.includes('backend') && (n.id.includes('backend') || n.id.includes('func')));
            const isAffected = isRoot || affectedNodeIds.has(n.id) || (affectedNodeIds.has('db') && n.id.includes('db')) || (affectedNodeIds.has('backend') && (n.id.includes('backend') || n.id.includes('func')));
            const isSelected = n.id === selectedTopologyNodeId;
            const atk = getNodeAttackBehavior(n.id, activeVuln);

            let nodeClass = 'topo-node';
            let statusBadge = '<span class="tag tag-low" style="font-size:9.5px; padding:1px 5px;">🟢 正常</span>';

            if (isSelected) {
                nodeClass += ' selected-node';
            }
            if (isRoot) {
                nodeClass += ' node-affected node-root-cause';
                statusBadge = '<span class="tag tag-critical" style="font-size:9.5px; padding:1px 5px;">💥 风险来源</span>';
            } else if (isAffected) {
                nodeClass += ' node-affected';
                statusBadge = '<span class="tag tag-high" style="font-size:9.5px; padding:1px 5px;">🚨 潜在影响</span>';
            }

            const xPct = ((n.svgX / 1200) * 100).toFixed(2);
            const yPx = Math.round(n.svgY * yRatio);

            let attackBadgeHtml = '';
            if (isRoot) {
                attackBadgeHtml = `<div class="node-attack-badge badge-root" style="font-size:9.5px; padding:2px 5px; margin-top:3px;">💥 漏洞源头: ${escapeHtml(atk.role)}</div>`;
            } else if (isAffected) {
                attackBadgeHtml = `<div class="node-attack-badge badge-affected" style="font-size:9.5px; padding:2px 5px; margin-top:3px;">🚨 渗透波及: ${escapeHtml(atk.role)}</div>`;
            }

            nodesHtml += `
            <div class="${nodeClass}" style="left:${xPct}%; top:${yPx}px; z-index:20;" onclick="window.toggleTopologyNodeDetail(${safeInlineArg(n.id)})" title="${escapeHtml(n.title)} - 点击展开深度详情">
                <div class="topo-node-header">
                    <div class="topo-node-title">${escapeHtml(n.title)}</div>
                    ${statusBadge}
                </div>
                <div class="topo-node-tech" title="${escapeHtml(n.tech)}">${escapeHtml(n.tech)}</div>
                ${attackBadgeHtml}
            </div>
            `;
        });

        // 6. 如果选中了某个节点，生成右侧浮层滑出大卡片超级详细介绍
        let sideDetailCardHtml = '';
        if (selectedTopologyNodeId) {
            const selNode = nodes.find(n => n.id === selectedTopologyNodeId) || nodes[0];
            const isRoot = selNode.id === rootCauseNodeId;
            const isAffected = affectedNodeIds.has(selNode.id);
            const d = selNode.details || {};
            const curAtk = getNodeAttackBehavior(selNode.id, activeVuln);

            sideDetailCardHtml = `
            <div class="topo-node-detail-panel">
                <div class="topo-detail-header">
                    <div class="topo-detail-title">
                        <span style="font-size:16px; font-weight:800; color:#0f172a;">${escapeHtml(selNode.title)} · 深度架构大卡片</span>
                    </div>
                    <button class="btn btn-primary" style="padding:4px 10px; font-size:12px;" onclick="window.toggleTopologyNodeDetail(${safeInlineArg(selNode.id)})">✕ 关闭大卡片</button>
                </div>

                <div class="topo-detail-badge-group">
                    <span class="tag" style="background:#f1f5f9; color:#475569; font-size:11px;">${escapeHtml(selNode.subTitle)}</span>
                    <span class="tag ${isRoot ? 'tag-critical' : (isAffected ? 'tag-high' : 'tag-low')}" style="font-size:11px;">
                        ${isRoot ? '💥 风险来源组件' : (isAffected ? '🚨 潜在影响组件' : '🟢 未关联发现')}
                    </span>
                </div>

                <!-- 💥 当前漏洞下本组件的渗透与危害表现 -->
                <div class="topo-detail-section" style="background:${isRoot ? '#fee2e2' : (isAffected ? '#fff1f2' : '#f0fdf4')}; border-color:${isRoot ? '#f87171' : (isAffected ? '#fecdd3' : '#bbf7d0')};">
                    <h5 style="color:${isRoot ? '#991b1b' : (isAffected ? '#b91c1c' : '#15803d')};">🔍 当前风险在本组件上的观测与影响研判</h5>
                    <p><strong>状态判定：</strong> <span style="font-weight:700;">${escapeHtml(curAtk.role)}</span></p>
                    <p><strong>攻击行为还原：</strong> ${escapeHtml(curAtk.text)}</p>
                </div>

                <!-- 1. 技术栈与架构环境 -->
                <div class="topo-detail-section">
                    <h5>⚙️ 核心技术栈与通信协议</h5>
                    <p><strong>组件架构：</strong> <code>${escapeHtml(d.framework || selNode.tech)}</code></p>
                    <p><strong>协议标准：</strong> <code>${escapeHtml(d.protocol || 'TCP / HTTP')}</code></p>
                    <p><strong>功能定位：</strong> ${escapeHtml(selNode.desc)}</p>
                    <p><strong>核心资产：</strong> <span style="color:#0284c7;">${escapeHtml(d.assets || '业务核心组件与配置文件')}</span></p>
                </div>

                <!-- 2. 安全策略与风险态势 -->
                <div class="topo-detail-section" style="${isAffected ? 'background:#fff1f2; border-color:#fecdd3;' : ''}">
                    <h5 style="${isAffected ? 'color:#991b1b;' : ''}">🛡️ 安全防护策略与风险暴露面</h5>
                    <p><strong>防护机制：</strong> ${escapeHtml(d.securityPolicy)}</p>
                    <p><strong>潜在威胁：</strong> <span style="color:#b45309;">${escapeHtml(d.threatSurface)}</span></p>
                    ${isAffected ? `
                        <div style="background:#fee2e2; border:1px solid #f87171; border-radius:4px; padding:6px 10px; margin-top:8px; color:#991b1b; font-weight:600;">
                            🚨 动态研判警报：当前选中的漏洞 [${escapeHtml(activeVuln ? activeVuln.title : '')}] 直接波及此节点，存在被黑客作为跳板或窃取数据的严重风险！
                        </div>
                    ` : '<div style="margin-top:6px; color:#16a34a; font-weight:600;">✔ 当前巡检未发现直接波及该组件的高危暴露隐患。</div>'}
                </div>

                <!-- 3. 专家加固配置 -->
                <div class="topo-detail-section" style="background:#f0fdf4; border-color:#bbf7d0;">
                    <h5 style="color:#15803d;">🛠️ 专家推荐安全加固与配置指引</h5>
                    <p style="color:#166534; line-height:1.6;">${escapeHtml(d.hardening)}</p>
                </div>

                <!-- 4. 法规与合规依据 -->
                <div class="topo-detail-section" style="background:#f8fafc; border-color:#e2e8f0;">
                    <h5 style="color:#4f46e5;">⚖️ 等保 2.0 与法律法规合规要求</h5>
                    <p style="color:#4338ca;">${escapeHtml(d.compliance || '请依据本单位适用的法规和安全基线复核。')}</p>
                </div>

                <div style="font-size:11px; color:#64748b; text-align:center; margin-top:4px;">
                    💡 点击左侧该节点小卡片或右上角 ✕ 即可收起此大卡片
                </div>
            </div>
            `;
        }

        // 7. 漏洞切换选择栏 (按漏洞类型智能聚合展示，防止上百条同类漏洞刷屏)
        let vulnSelectorHtml = '';
        if (highImpactFindings.length > 0) {
            // 智能聚合：将相同标题/类型的漏洞聚合展示
            const groupedVulnsMap = new Map();
            highImpactFindings.forEach((f, fIdx) => {
                const key = f.title || '未知隐患';
                if (!groupedVulnsMap.has(key)) {
                    groupedVulnsMap.set(key, {
                        title: f.title,
                        severity: f.severity || 'HIGH',
                        indices: [],
                        firstIndex: fIdx,
                        sampleUrl: f.url
                    });
                }
                groupedVulnsMap.get(key).indices.push(fIdx);
            });

            let pillsHtml = '';
            let groupIndex = 0;
            groupedVulnsMap.forEach((g) => {
                groupIndex++;
                const isAct = g.indices.includes(selectedTopologyFindingIndex);
                const countBadge = g.indices.length > 1 ? `<span style="background:rgba(0,0,0,0.07); padding:1px 6px; border-radius:10px; font-size:10px; font-weight:700; margin-left:4px;">共 ${g.indices.length} 处端点</span>` : '';
                pillsHtml += `
                <button class="topo-vuln-pill ${isAct ? 'active' : ''}" onclick="selectTopologyVuln(${g.firstIndex})" title="${escapeHtml(g.title)} (影响 ${g.indices.length} 处资源)">
                    <span class="tag tag-${escapeHtml(g.severity.toLowerCase())}" style="font-size:10px; padding:1px 4px;">${escapeHtml(g.severity)}</span>
                    <span>${groupIndex}. ${escapeHtml(g.title)}</span>
                    ${countBadge}
                </button>
                `;
            });

            vulnSelectorHtml = `
            <div class="topo-vuln-bar">
                <div style="font-size:12px; font-weight:700; color:#0f172a; margin-right:4px; white-space:nowrap;">
                    🎯 风险证据关联 (已智能聚合为 ${groupedVulnsMap.size} 类 / 共 ${highImpactFindings.length} 处隐患)：
                </div>
                ${pillsHtml}
                ${complianceHeaders.length > 0 ? `
                <div style="margin-left:auto; font-size:11px; color:#64748b; background:#f8fafc; border:1px solid #e2e8f0; padding:3px 8px; border-radius:4px; display:flex; align-items:center; gap:4px; white-space:nowrap;">
                    <span>📋 另含 ${complianceHeaders.length} 项基础合规标头建议</span>
                </div>
                ` : ''}
            </div>

            <!-- 风险证据、影响研判与复测流程可视化条 -->
            <div class="attack-process-card">
                <div class="attack-process-header">
                    <div class="attack-process-title">
                        <span>🔍 风险证据与复测流程 (Evidence & Retest Flow)</span>
                    </div>
                    <span class="tag tag-critical" style="font-size:10px;">${escapeHtml(activeVuln ? activeVuln.title : '安全运行')}</span>
                </div>
                <div class="attack-steps-container">
                    ${attackStepsHtml}
                </div>
            </div>

            <div style="background:#fff1f2; border:1px solid #fecdd3; border-radius:6px; padding:10px 14px; margin:10px 14px 0 14px; font-size:12px; color:#991b1b; display:flex; align-items:center; gap:8px;">
                <span style="font-size:16px;">🚨</span>
                <div>
                    <strong>当前选中的漏洞：</strong> [${escapeHtml(activeVuln.severity)}] ${escapeHtml(activeVuln.title)} (<code>${escapeHtml(activeVuln.url)}</code>)<br>
                    <span style="color:#b91c1c;">${impactAnalysisText}</span>
                </div>
            </div>
            `;
        } else if (complianceHeaders.length > 0) {
            let pillsHtml = '';
            complianceHeaders.forEach((f, fIdx) => {
                const isAct = fIdx === selectedTopologyFindingIndex ? 'active' : '';
                const sev = f.severity || 'LOW';
                pillsHtml += `
                <button class="topo-vuln-pill ${isAct}" onclick="selectTopologyVuln(${fIdx})">
                    <span class="tag tag-${escapeHtml(sev.toLowerCase())}" style="font-size:10px; padding:1px 4px;">${escapeHtml(sev)}</span>
                    <span>${fIdx + 1}. ${escapeHtml(f.title)}</span>
                </button>
                `;
            });

            vulnSelectorHtml = `
            <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; padding:12px 16px; margin:10px 14px 0 14px; font-size:13px; color:#15803d; display:flex; align-items:center; justify-content:space-between;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:18px;">🛡️</span>
                    <div>
                        <strong>当前检测范围内未检出高危渗透漏洞或攻击链</strong>。该结论不代表目标不存在其他风险。
                        <div style="font-size:12px; color:#475569; margin-top:2px;">检测到 ${complianceHeaders.length} 项基础安全响应标头建议 (点击下方查看详情)：</div>
                    </div>
                </div>
            </div>
            <div class="topo-vuln-bar" style="margin-top:8px;">
                <div style="font-size:12px; font-weight:700; color:#475569; margin-right:4px;">
                    📋 基础安全防护标头建议 (共 ${complianceHeaders.length} 项)：
                </div>
                ${pillsHtml}
            </div>
            `;
        } else {
            vulnSelectorHtml = `
            <div style="background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; padding:12px 16px; margin:10px 14px 0 14px; font-size:13px; color:#15803d; display:flex; align-items:center; gap:8px;">
                <span style="font-size:18px;">🎉</span>
                <div><strong>${focusPageUrl ? `目标页面 [${escapeHtml(focusPageUrl)}] 在当前启用规则下未检出问题` : '当前启用的检测项未返回安全发现'}</strong>。该结论不代表目标不存在其他风险。</div>
            </div>
            `;
        }

        // 8. 下部资产树过滤
        const filtered = sitemap.filter(s => currentSitemapFilter === 'ALL' || s.type === currentSitemapFilter);
        let rows = '';
        filtered.forEach(s => {
            const typeBadge = {
                PAGE: '<span class="tag tag-low">网页 (HTML)</span>',
                API: '<span class="tag tag-info">接口 (API)</span>',
                STATIC: '<span class="tag tag-medium">静态文件</span>',
                EXTERNAL: '<span class="tag tag-high">外部链接</span>'
            }[s.type || 'PAGE'] || '<span class="tag tag-info">资源</span>';

            rows += `<tr>
                <td>${typeBadge}</td>
                <td><code style="color:#0284c7;">${escapeHtml(s.url)}</code></td>
                <td><strong>${escapeHtml(s.title || '--')}</strong></td>
                <td><span class="tag tag-low">${escapeHtml(s.status ?? '未知')}</span></td>
            </tr>`;
        });

        return `
        <div style="display:flex; flex-direction:column; gap:20px;">
            <!-- 视觉化连线拓扑图与漏洞标红卡片 -->
            <div class="card" style="padding:0; overflow:hidden;">
                <div class="card-title" style="padding:14px 16px; border-bottom:1px solid var(--border-color); margin:0; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                    <div>
                        <span>🏛️ 系统连线拓扑图与漏洞影响扩散分析 (Connected System Topology)</span>
                        <span style="font-size:12px; color:#64748b; display:block; margin-top:2px;">四层分级舒展排版 · 点击任意小卡片可唤起浮层深度透视 · 连线与漏洞受影响节点动态爆红</span>
                    </div>

                    <!-- 动态拉长/展开与在新窗口打开控制栏 -->
                    <div style="display:flex; gap:6px; align-items:center;">
                        <span style="font-size:12px; color:#64748b;">纵向高度:</span>
                        <button class="btn ${topologyCanvasHeight === 1050 ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="changeTopologyHeight(1050)">📐 紧凑全览 (1050px)</button>
                        <button class="btn ${topologyCanvasHeight === 1200 ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="changeTopologyHeight(1200)">↕️ 黄金标准 (1200px)</button>
                        <button class="btn ${topologyCanvasHeight === 1450 ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="changeTopologyHeight(1450)">🚀 宽松舒展 (1450px)</button>
                        <button class="btn" style="font-size:11px; padding:2px 8px; margin-left:6px; background:#f0f9ff; color:#0284c7; border-color:#bae6fd;" onclick="openTopologyInNewTab()">🌐 在新标签页全屏打开</button>
                    </div>
                </div>

                ${vulnSelectorHtml}

                <div class="topo-layout-container">
                    <div class="topo-canvas-wrapper" style="height:${topologyCanvasHeight}px; min-height:${topologyCanvasHeight}px;">
                        <!-- SVG 连线层 (1200 x ${topologyCanvasHeight} 空间，横向 100% 响应式等比拉伸) -->
                        <svg class="topo-svg-layer" viewBox="0 0 1200 ${topologyCanvasHeight}" preserveAspectRatio="none">
                            ${svgLinesHtml}
                        </svg>

                        <!-- HTML 交互节点层 -->
                        <div class="topo-nodes-layer">
                            ${nodesHtml}
                        </div>

                        <!-- 浮层滑出模式详情大卡片 -->
                        ${sideDetailCardHtml}
                    </div>
                </div>
            </div>

            <!-- 资产端点清单 (自动随上面卡片拉长而平滑下移) -->
            <div class="card">
                <div class="card-title">
                    <span>🌐 网站发现了哪些页面和接口？(共 ${sitemap.length} 个节点)</span>
                    <div style="display:flex; gap:6px;">
                        <button class="btn ${currentSitemapFilter === 'ALL' ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="filterSitemap('ALL')">全部 (${sitemap.length})</button>
                        <button class="btn ${currentSitemapFilter === 'PAGE' ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="filterSitemap('PAGE')">网页 HTML</button>
                        <button class="btn ${currentSitemapFilter === 'API' ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="filterSitemap('API')">API 接口</button>
                        <button class="btn ${currentSitemapFilter === 'STATIC' ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="filterSitemap('STATIC')">静态资源</button>
                        <button class="btn ${currentSitemapFilter === 'EXTERNAL' ? 'btn-primary' : ''}" style="font-size:11px; padding:2px 8px;" onclick="filterSitemap('EXTERNAL')">外部链接</button>
                    </div>
                </div>
                <table class="data-table">
                    <thead><tr><th>资源类别</th><th>发现的网址路径</th><th>页面标题 / 资源说明</th><th>HTTP 状态</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="4" style="text-align:center; color:#64748b;">该分类下暂无资产</td></tr>'}</tbody>
                </table>
            </div>
        </div>`;
    } else if (currentBurpSubTab === 'logger') {
        // ---------------- 📜 HTTP 探针流量与审计日志 (LOGGER) ----------------
        if (logs.length === 0) {
            return `<div class="card"><p style="color:#64748b; padding:20px; text-align:center;">暂无探针记录</p></div>`;
        }
        let rows = '';
        logs.forEach((l, idx) => {
            rows += `<tr>
                <td>${escapeHtml((l.timestamp || '').replace('T', ' ').substring(0, 19))}</td>
                <td><span class="tag tag-low">${escapeHtml(l.action)}</span></td>
                <td><code>${escapeHtml(l.target)}</code></td>
                <td>${escapeHtml(l.details)}</td>
                <td><span class="tag tag-${l.status === 'SUCCESS' ? 'low' : 'critical'}">${l.status === 'SUCCESS' ? '成功' : escapeHtml(l.status)}</span></td>
                <td>
                    <button class="btn btn-primary" style="font-size:11px; padding:2px 8px;" onclick="viewRawProbeTraffic(${safeInlineArg(l.target)}, ${safeInlineArg(l.action)}, ${safeInlineArg(l.details)})">
                        🔍 查看报文
                    </button>
                </td>
            </tr>`;
        });
        return `
        <div class="card">
            <div class="card-title"><span>📜 扫描引擎发出的所有探针请求与 HTTP 报文 (Logger)</span></div>
            <table class="data-table">
                <thead><tr><th>时间</th><th>操作动作</th><th>目标网址 / 端点</th><th>探针流水与判定详情</th><th>状态</th><th>报文操作</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
    }
}

function viewRawProbeTraffic(target, action, details) {
    let path = '/';
    let host = 'target';
    try {
        const u = new URL(target);
        path = u.pathname + u.search;
        host = u.host;
    } catch(e) {}

    const reqStr = `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: DAS-SentinelAgent/1.0 (Security Probe; DAS-AI)\r\nAccept: text/html,application/xhtml+xml,application/json,*/*\r\nAccept-Language: zh-CN,zh;q=0.9\r\nConnection: close\r\n`;
    const respStr = `[未保存原始 HTTP 响应，以下仅为审计事件]\r\n\r\nAction: ${action}\r\nTarget: ${target}\r\nDetails: ${details}`;
    window.currentProbeTraffic = { request: reqStr, response: respStr };

    document.getElementById('modal-title').innerText = `[HTTP 探测报文] ${action} - ${target}`;
    document.getElementById('modal-body').innerHTML = `
    <div class="burp-http-tabs" style="margin-bottom:10px;">
        <button class="http-tab-btn active" id="modal-tab-req" onclick="switchRawProbeTraffic('request')">Request (发出的请求报文)</button>
        <button class="http-tab-btn" id="modal-tab-resp" onclick="switchRawProbeTraffic('response')">Response (收到的响应报文)</button>
    </div>
    <pre id="modal-http-box" style="background:#fafafa; border:1px solid #e2e8f0; border-radius:6px; padding:12px; font-family:monospace; font-size:12px; color:#0f172a; white-space:pre-wrap; word-break:break-all; max-height:400px; overflow:auto;">${escapeHtml(reqStr)}</pre>
    <div style="margin-top:14px; text-align:right;">
        <button class="btn btn-primary" onclick="navigator.clipboard.writeText(document.getElementById('modal-http-box').innerText); alert('报文已复制至剪贴板！');">📋 一键复制当前报文</button>
    </div>
    `;
    document.getElementById('evidence-modal').style.display = 'flex';
}

function getNodeAttackBehavior(nodeId, activeVuln) {
    if (!activeVuln) {
        return { status: 'safe', role: '🟢 未关联风险', text: '当前未选择风险发现。' };
    }
    const verified = activeVuln.verified === 1 || activeVuln.verified === true;
    const evidenceState = verified ? '已取得响应证据' : '待人工复核';
    const labels = {
        user: ['affected', '🔵 请求来源', '授权巡检请求从此处发起'],
        frontend: ['affected', '🟠 页面/资源观测', '关联到已发现页面或静态资源'],
        cdn: ['affected', '🟠 接入层观测', '仅表示请求经过目标接入层，不推断具体厂商'],
        backend: ['affected', '🟠 应用层研判', '仅根据当前风险证据评估潜在影响'],
        db: ['affected', '🟠 数据层研判', '需要业务方结合资产台账进一步确认'],
        auth: ['affected', '🟠 边界研判', '授权、鉴权与边界配置需结合证据复核']
    };
    const item = labels[nodeId] || ['safe', '⚪ 未关联', '当前风险没有保存与该层直接相关的证据'];
    return { status: item[0], role: item[1], text: `${item[2]}（${evidenceState}）` };
}

function switchRawProbeTraffic(kind) {
    const traffic = window.currentProbeTraffic || {};
    const isRequest = kind === 'request';
    const box = document.getElementById('modal-http-box');
    if (box) box.innerText = isRequest ? (traffic.request || '') : (traffic.response || '');
    document.getElementById('modal-tab-req')?.classList.toggle('active', isRequest);
    document.getElementById('modal-tab-resp')?.classList.toggle('active', !isRequest);
}

function filterSitemap(filterType) {
    currentSitemapFilter = filterType;
    renderBurpScannerLayout(currentTaskDetailData);
}

async function retestSingleFindingLive(findingId) {
    try {
        const res = await fetch(`${API_BASE}/findings/${findingId}/retest`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        const r = data.retest_result || {};
        if (!r.retested) {
            alert(`【复测失败】无法判断是否已修复，原状态保持不变。\n原因：${r.reason || '服务未返回可验证证据'}`);
        } else if (r.is_still_vulnerable) {
            alert(`【复测结论】⚠️ 问题仍存在！\n原因：${r.reason || '复测证据仍匹配'}\n状态保持为 OPEN`);
        } else {
            alert(`【复测结论】🎉 已经修好啦！\n原因：${r.reason || '复测未再观察到原证据'}\n状态已自动更新为 FIXED (已修复)`);
        }
        await refreshTaskDetailsLive();
    } catch (e) {
        alert('复测请求失败: ' + e);
    }
}

function escapeHtml(string) {
    return String(string ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Encode a value as a complete JavaScript string literal, then protect the
// surrounding HTML attribute. This is safer than interpolating quoted values.
function safeInlineArg(value) {
    return escapeHtml(JSON.stringify(String(value ?? '')));
}

function extractRootSiteUrl(rawUrl) {
    if (!rawUrl) return '';
    try {
        const u = new URL(rawUrl);
        return `${u.protocol}//${u.host}`;
    } catch (e) {
        return rawUrl;
    }
}

/* ---------------- 4. FINDINGS ---------------- */
function getFindingsHTML() {
    return `
    <div class="card" style="margin-bottom:20px;">
        <div class="card-title"><span>🔍 筛选与查找安全问题</span></div>
        <div class="grid-4" style="margin-bottom:10px;">
            <div class="form-group">
                <label class="form-label">问题类别</label>
                <select id="filter-cat" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部类别</option>
                    <option value="VULN">源码与配置弱点 (VULN)</option>
                    <option value="SENSITIVE">敏感数据与隐私 (SENSITIVE)</option>
                    <option value="TAMPER">页面篡改与暗链 (TAMPER)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">危险级别</label>
                <select id="filter-sev" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部等级</option>
                    <option value="CRITICAL">严重 (Critical - 极危险)</option>
                    <option value="HIGH">高危 (High - 严重)</option>
                    <option value="MEDIUM">中危 (Medium - 需关注)</option>
                    <option value="LOW">低危 (Low - 建议加固)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">人工审核与流转状态</label>
                <select id="filter-status" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部隐患记录</option>
                    <option value="CONFIRMED">🛡️ 仅看【专家已认证】实战漏洞</option>
                    <option value="OPEN">⏳ 仅看【待人工审核】初筛隐患</option>
                    <option value="FALSE_POSITIVE">❌ 仅看【已标记误报/已排除】记录</option>
                    <option value="FIXED">✔ 仅看【已修复】记录</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">🎯 漏洞收录标准 (SRC / 基线)</label>
                <select id="filter-src" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部记录 (含基线与实战)</option>
                    <option value="SRC_EXPLOITABLE">🎯 仅看 SRC 有效实战漏洞 (具备真实威胁)</option>
                    <option value="BASELINE_HYGIENE">📋 仅看安全配置基线与合规建议</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">巡检主网址分类 (Root URL)</label>
                <select id="filter-url" class="form-select" onchange="filterFindingsByUrl(this.value)">
                    <option value="">全部巡检站点 (全部资产)</option>
                </select>
            </div>
        </div>

        <!-- 巡检主网址快速分类胶囊标签栏 (按主任务目标网址分类) -->
        <div id="url-pills-box" class="url-filter-bar">
            <span style="font-size:12px; font-weight:700; color:#0f172a; margin-right:4px;">🌐 巡检主网址分类：</span>
            <button class="url-filter-pill active" onclick="filterFindingsByUrl('')">全部巡检站点</button>
        </div>
    </div>

    <!-- 📊 动态双圆形状态图看板：人工认证态势 vs 待审核初筛态势 -->
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap:16px; margin-bottom:20px;">
        <!-- 原型图 1: 🛡️ 专家人工已认证 · 实战高危漏洞态势 -->
        <div class="card" style="border-top:4px solid #16a34a; background:#ffffff; box-shadow:0 2px 8px rgba(0,0,0,0.04); margin-bottom:0;">
            <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#15803d; font-weight:700; font-size:14px;">🛡️ 原型图 1: 专家人工已认证 · 实战漏洞态势</span>
                <span class="tag tag-low" style="font-size:11px;">已人工核实威胁</span>
            </div>
            <div style="display:flex; gap:16px; align-items:center; flex-wrap:wrap; margin-top:8px;">
                <div style="position:relative; width:200px; height:200px; flex-shrink:0; display:flex; align-items:center; justify-content:center;">
                    <svg id="confirmed-donut-svg" width="200" height="200" viewBox="0 0 260 260">
                        <circle cx="130" cy="130" r="56" fill="none" stroke="#f1f5f9" stroke-width="16" />
                    </svg>
                    <div style="position:absolute; text-align:center; pointer-events:none;">
                        <div id="confirmed-total-count" style="font-size:22px; font-weight:800; color:#15803d; line-height:1;">0</div>
                        <div style="font-size:10.5px; color:#64748b; margin-top:3px;">人工已确认</div>
                    </div>
                </div>
                <div id="confirmed-stats-box" style="flex:1; min-width:180px; display:grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap:8px;">
                </div>
            </div>
            <div style="font-size:11px; color:#15803d; background:#f0fdf4; border:1px solid #bbf7d0; padding:6px 10px; border-radius:6px; margin-top:10px;">
                ✔ 仅统计经网安专家/SRC人员人工核实验证的真实漏洞，已排除所有误报。
            </div>
        </div>

        <!-- 原型图 2: ⏳ 智能体初筛 · 待人工审核隐患态势 -->
        <div class="card" style="border-top:4px solid #d97706; background:#ffffff; box-shadow:0 2px 8px rgba(0,0,0,0.04); margin-bottom:0;">
            <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#b45309; font-weight:700; font-size:14px;">⏳ 原型图 2: 智能体初筛 · 待人工复核态势</span>
                <span class="tag tag-medium" style="font-size:11px;">待专家审核</span>
            </div>
            <div style="display:flex; gap:16px; align-items:center; flex-wrap:wrap; margin-top:8px;">
                <div style="position:relative; width:200px; height:200px; flex-shrink:0; display:flex; align-items:center; justify-content:center;">
                    <svg id="pending-donut-svg" width="200" height="200" viewBox="0 0 260 260">
                        <circle cx="130" cy="130" r="56" fill="none" stroke="#f1f5f9" stroke-width="16" />
                    </svg>
                    <div style="position:absolute; text-align:center; pointer-events:none;">
                        <div id="pending-total-count" style="font-size:22px; font-weight:800; color:#b45309; line-height:1;">0</div>
                        <div style="font-size:10.5px; color:#64748b; margin-top:3px;">待人工复核</div>
                    </div>
                </div>
                <div id="pending-stats-box" style="flex:1; min-width:180px; display:grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap:8px;">
                </div>
            </div>
            <div style="font-size:11px; color:#92400e; background:#fffbeb; border:1px solid #fde68a; padding:6px 10px; border-radius:6px; margin-top:10px;">
                💡 智能巡检初筛出的风险线索，可在下方表格中点击「✅ 确认」移入认证图，或「❌ 标记误报」直接剔除。
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-title" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
            <div>
                <span>🛡️ 发现的全部风险问题与证据清单</span>
                <span id="findings-count-badge" style="font-size:12px; color:#64748b; margin-left:6px;"></span>
            </div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#f0fdf4; color:#15803d; border-color:#bbf7d0;" onclick="batchConfirmCriticalFindings()">✅ 一键认证所有严重/高危漏洞</button>
                <button class="btn" style="font-size:11px; padding:3px 10px; color:#dc2626;" onclick="batchClearFalsePositives()">❌ 一键排除当前筛选为误报</button>
                <button class="btn" style="font-size:11px; padding:3px 10px;" onclick="loadFindingsTable()">🔄 刷新列表</button>
            </div>
        </div>
        <div id="findings-table-box">正在加载风险记录...</div>
    </div>

    <!-- 证据链详情模态框 -->
    <div id="evidence-modal" class="modal-overlay">
        <div class="modal-content">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <h3 id="modal-title" style="color:#0f172a; font-size:16px;">问题详情与现场证据</h3>
                <button onclick="document.getElementById('evidence-modal').style.display='none'" class="btn" style="padding:2px 8px;">✕</button>
            </div>
            <div id="modal-body" style="font-size:13px; line-height:1.6;"></div>
        </div>
    </div>
    `;
}

function filterFindingsByUrl(urlStr) {
    selectedUrlFilter = urlStr;
    const sel = document.getElementById('filter-url');
    if (sel) sel.value = urlStr;
    
    // 更新 pill active 状态
    document.querySelectorAll('.url-filter-pill').forEach(pill => {
        if ((!urlStr && pill.innerText.startsWith('全部巡检站点')) || (urlStr && pill.innerText.includes(urlStr))) {
            pill.classList.add('active');
        } else {
            pill.classList.remove('active');
        }
    });

    loadFindingsTable();
}

function renderSingleDonutChart(prefix, findingsList) {
    const svgElem = document.getElementById(`${prefix}-donut-svg`);
    const totalElem = document.getElementById(`${prefix}-total-count`);
    const statsBox = document.getElementById(`${prefix}-stats-box`);
    
    const totalCount = findingsList.length;
    if (totalElem) totalElem.innerText = totalCount;

    const sevCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };
    findingsList.forEach(f => {
        const s = (f.severity || 'INFO').toUpperCase();
        if (sevCounts[s] !== undefined) sevCounts[s]++;
        else sevCounts.INFO++;
    });

    const sevConfig = [
        { key: 'CRITICAL', label: '严重', color: '#dc2626', bg: '#fee2e2', text: '#991b1b', border: '#fca5a5' },
        { key: 'HIGH', label: '高危', color: '#ea580c', bg: '#ffedd5', text: '#9a3412', border: '#fdba74' },
        { key: 'MEDIUM', label: '中危', color: '#d97706', bg: '#fef3c7', text: '#92400e', border: '#fde68a' },
        { key: 'LOW', label: '低危', color: '#2563eb', bg: '#dbeafe', text: '#1e40af', border: '#bfdbfe' },
        { key: 'INFO', label: '提示', color: '#64748b', bg: '#f1f5f9', text: '#334155', border: '#cbd5e1' }
    ];

    if (!svgElem || !statsBox) return;

    if (totalCount === 0) {
        svgElem.innerHTML = `<circle cx="130" cy="130" r="56" fill="none" stroke="#e2e8f0" stroke-width="16" />`;
        statsBox.innerHTML = `<div style="grid-column: 1 / -1; color:#64748b; font-size:12px; padding:10px 0; text-align:center;">暂无匹配记录</div>`;
        return;
    }

    const cx = 130;
    const cy = 130;
    const R = 56;
    const C = 2 * Math.PI * R; // 351.858377
    let offset = 0;
    let circleArcs = '';
    let outerLabels = '';
    let cardsHtml = '';

    sevConfig.forEach(cfg => {
        const count = sevCounts[cfg.key] || 0;
        const percentVal = totalCount > 0 ? ((count / totalCount) * 100).toFixed(1) : 0;
        const percentStr = `${percentVal}%`;

        if (count > 0) {
            const dashLength = (count / totalCount) * C;

            // 1. 环形扇区
            circleArcs += `
            <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="${cfg.color}" stroke-width="16" 
                    stroke-dasharray="${dashLength.toFixed(2)} ${(C - dashLength).toFixed(2)}" 
                    stroke-dashoffset="${(-offset).toFixed(2)}"
                    style="transition: all 0.5s ease; cursor:pointer;"
                    onclick="quickFilterSeverity('${cfg.key}')">
                <title>${cfg.label}: ${count} 处 (${percentStr}) - 点击筛选</title>
            </circle>
            `;

            // 2. 外围指示线
            const startDeg = (offset / C) * 360 - 90;
            const spanDeg = (dashLength / C) * 360;
            const midDeg = startDeg + spanDeg / 2;
            const rad = midDeg * Math.PI / 180;

            const rStart = R + 10;
            const x1 = cx + rStart * Math.cos(rad);
            const y1 = cy + rStart * Math.sin(rad);

            const rLabel = R + 38;
            const x2 = cx + rLabel * Math.cos(rad);
            const y2 = cy + rLabel * Math.sin(rad);

            const badgeW = percentStr.length * 7.5 + 8;

            outerLabels += `
            <g style="cursor:pointer;" onclick="quickFilterSeverity('${cfg.key}')" title="${cfg.label}: ${count} 处 (${percentStr})">
                <line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" 
                      stroke="${cfg.color}" stroke-width="1.2" stroke-dasharray="2,2" opacity="0.85" />
                <rect x="${(x2 - badgeW / 2).toFixed(1)}" y="${(y2 - 9).toFixed(1)}" width="${badgeW}" height="18" rx="4" 
                      fill="${cfg.bg}" stroke="${cfg.color}" stroke-width="1" />
                <text x="${x2.toFixed(1)}" y="${(y2 + 3.8).toFixed(1)}" text-anchor="middle" font-size="10" font-weight="800" fill="${cfg.text}">
                    ${percentStr}
                </text>
            </g>
            `;

            offset += dashLength;
        }

        cardsHtml += `
        <div onclick="quickFilterSeverity('${cfg.key}')" 
             style="background:#ffffff; border:1px solid ${count > 0 ? cfg.border : '#e2e8f0'}; border-radius:8px; padding:6px 8px; cursor:pointer; transition:all 0.2s ease;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:11px; font-weight:700; color:${cfg.color};">${cfg.label}</span>
                <span style="font-size:10px; color:#64748b;">${percentStr}</span>
            </div>
            <div style="display:flex; align-items:baseline; gap:2px; margin-top:2px;">
                <span style="font-size:15px; font-weight:800; color:${cfg.text};">${count}</span>
                <span style="font-size:10px; color:#64748b;">处</span>
            </div>
        </div>
        `;
    });

    svgElem.innerHTML = `
    <g transform="rotate(-90 ${cx} ${cy})">
        ${circleArcs}
    </g>
    <g>
        ${outerLabels}
    </g>
    `;
    statsBox.innerHTML = cardsHtml;
}

let currentFindingsWorkflowTab = 'pending'; // 'pending' | 'confirmed' | 'trash'
window.selectedFindingIds = new Set();

window.switchFindingsWorkflowTab = function(tabName) {
    currentFindingsWorkflowTab = tabName;
    
    // 同步选项卡高亮状态
    document.querySelectorAll('.burp-tab-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById(`tab-btn-${tabName}`);
    if (activeBtn) activeBtn.classList.add('active');
    
    const selectAllCheckbox = document.getElementById('selectAllFindings');
    if (selectAllCheckbox) selectAllCheckbox.checked = false;
    window.selectedFindingIds.clear();
    
    loadFindingsTable();
};

window.toggleSelectAllFindings = function(checked) {
    const checkboxes = document.querySelectorAll('.finding-row-checkbox');
    window.selectedFindingIds.clear();
    checkboxes.forEach(cb => {
        cb.checked = checked;
        if (checked) window.selectedFindingIds.add(cb.value);
    });
};

window.toggleSingleFinding = function(id, checked) {
    if (checked) window.selectedFindingIds.add(id);
    else window.selectedFindingIds.delete(id);
    
    const selectAllCheckbox = document.getElementById('selectAllFindings');
    const checkboxes = document.querySelectorAll('.finding-row-checkbox');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = (window.selectedFindingIds.size > 0 && window.selectedFindingIds.size === checkboxes.length);
    }
};

window.batchConfirmSelected = async function() {
    if (window.selectedFindingIds.size === 0) return alert('请先勾选需要操作的漏洞记录！');
    try {
        await fetch(`${API_BASE}/findings/batch-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding_ids: Array.from(window.selectedFindingIds), status: 'CONFIRMED' })
        });
        window.selectedFindingIds.clear();
        loadFindingsTable();
    } catch(e) { console.error(e); }
};

window.batchFalsePositiveSelected = async function() {
    if (window.selectedFindingIds.size === 0) return alert('请先勾选需要操作的漏洞记录！');
    try {
        await fetch(`${API_BASE}/findings/batch-status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding_ids: Array.from(window.selectedFindingIds), status: 'FALSE_POSITIVE' })
        });
        window.selectedFindingIds.clear();
        loadFindingsTable();
    } catch(e) { console.error(e); }
};

window.batchDeleteSelected = async function() {
    if (window.selectedFindingIds.size === 0) return alert('请先勾选需要彻底删除的记录！');
    try {
        await fetch(`${API_BASE}/findings/batch-delete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding_ids: Array.from(window.selectedFindingIds) })
        });
        window.selectedFindingIds.clear();
        loadFindingsTable();
    } catch(e) { console.error(e); }
};

window.setFindingStatusDirect = async function(id, newStatus) {
    try {
        await fetch(`${API_BASE}/findings/${id}/status?status=${newStatus}`, { method: 'POST' });
        loadFindingsTable();
    } catch (e) {
        console.error('状态更新失败:', e);
    }
};

window.deleteFindingDirect = async function(id) {
    try {
        await fetch(`${API_BASE}/findings/${id}`, { method: 'DELETE' });
        loadFindingsTable();
    } catch (e) {
        console.error('删除失败:', e);
    }
};

window.cleanupAllFalsePositivesDirect = async function() {
    try {
        await fetch(`${API_BASE}/findings/cleanup-false-positives`, { method: 'POST' });
        loadFindingsTable();
    } catch (e) {
        console.error('清空误报失败:', e);
    }
};

window.batchConfirmCriticalFindingsDirect = async function() {
    try {
        const res = await fetch(`${API_BASE}/findings`);
        const all = await res.json();
        const targetIds = all.filter(f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.status === 'OPEN').map(f => f.id);
        if (targetIds.length > 0) {
            await fetch(`${API_BASE}/findings/batch-status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding_ids: targetIds, status: 'CONFIRMED' })
            });
        }
        loadFindingsTable();
    } catch (e) {
        console.error('批量确认失败:', e);
    }
};

window.batchClearFalsePositivesDirect = async function() {
    try {
        const res = await fetch(`${API_BASE}/findings`);
        const all = await res.json();
        const targetIds = all.filter(f => f.status === 'OPEN').map(f => f.id);
        if (targetIds.length > 0) {
            await fetch(`${API_BASE}/findings/batch-status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ finding_ids: targetIds, status: 'FALSE_POSITIVE' })
            });
        }
        loadFindingsTable();
    } catch (e) {
        console.error('批量排除失败:', e);
    }
};

function getFindingsHTML() {
    return `
    <div class="card" style="margin-bottom:20px;">
        <div class="card-title"><span>🔍 风险漏洞与隐患智能筛选中心</span></div>
        <div class="filter-bar">
            <div class="form-group">
                <label class="form-label">风险分类</label>
                <select id="filter-cat" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部分类</option>
                    <option value="VULN">应用安全漏洞 (VULN)</option>
                    <option value="SENSITIVE">敏感信息泄露 (SENSITIVE)</option>
                    <option value="TAMPER">网页内容合规 (TAMPER)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">严重级别 (SRC 标准)</label>
                <select id="filter-sev" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部严重等级</option>
                    <option value="CRITICAL">严重 (Critical - 极高危)</option>
                    <option value="HIGH">高危 (High - 严重)</option>
                    <option value="MEDIUM">中危 (Medium - 需关注)</option>
                    <option value="LOW">低危 (Low - 建议加固)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">🎯 漏洞收录标准 (SRC / 基线)</label>
                <select id="filter-src" class="form-select" onchange="loadFindingsTable()">
                    <option value="">全部记录 (含基线与实战)</option>
                    <option value="SRC_EXPLOITABLE">🎯 仅看 SRC 有效实战漏洞 (具备真实威胁)</option>
                    <option value="BASELINE_HYGIENE">📋 仅看安全配置基线与合规建议</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">巡检主网址分类 (Root URL)</label>
                <select id="filter-url" class="form-select" onchange="filterFindingsByUrl(this.value)">
                    <option value="">全部巡检站点 (全部资产)</option>
                </select>
            </div>
        </div>

        <!-- 巡检主网址快速分类胶囊标签栏 -->
        <div id="url-pills-box" class="url-filter-bar">
            <span style="font-size:12px; font-weight:700; color:#0f172a; margin-right:4px;">🌐 巡检主网址分类：</span>
            <button class="url-filter-pill active" onclick="filterFindingsByUrl('')">全部巡检站点</button>
        </div>
    </div>

    <!-- 📊 动态双圆形状态图看板：人工认证态势 vs 待审核初筛态势 -->
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(420px, 1fr)); gap:16px; margin-bottom:20px;">
        <!-- 原型图 1: 🛡️ 专家人工已认证 · 实战高危漏洞态势 -->
        <div class="card" style="border-top:4px solid #16a34a; background:#ffffff; box-shadow:0 2px 8px rgba(0,0,0,0.04); margin-bottom:0;">
            <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#15803d; font-weight:700; font-size:14px;">🛡️ 原型图 1: 专家人工已认证 · 实战漏洞态势</span>
                <span class="tag tag-low" style="font-size:11px;">已人工核实威胁</span>
            </div>
            <div style="display:flex; gap:16px; align-items:center; flex-wrap:wrap; margin-top:8px;">
                <div style="position:relative; width:200px; height:200px; flex-shrink:0; display:flex; align-items:center; justify-content:center;">
                    <svg id="confirmed-donut-svg" width="200" height="200" viewBox="0 0 260 260">
                        <circle cx="130" cy="130" r="56" fill="none" stroke="#f1f5f9" stroke-width="16" />
                    </svg>
                    <div style="position:absolute; text-align:center; pointer-events:none;">
                        <div id="confirmed-total-count" style="font-size:22px; font-weight:800; color:#15803d; line-height:1;">0</div>
                        <div style="font-size:10.5px; color:#64748b; margin-top:3px;">人工已确认</div>
                    </div>
                </div>
                <div id="confirmed-stats-box" style="flex:1; min-width:180px; display:grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap:8px;">
                </div>
            </div>
            <div style="font-size:11px; color:#15803d; background:#f0fdf4; border:1px solid #bbf7d0; padding:6px 10px; border-radius:6px; margin-top:10px;">
                ✔ 仅统计经网安专家/SRC人员人工核实验证的真实漏洞，已排除所有误报。
            </div>
        </div>

        <!-- 原型图 2: ⏳ 智能体初筛 · 待人工审核隐患态势 -->
        <div class="card" style="border-top:4px solid #d97706; background:#ffffff; box-shadow:0 2px 8px rgba(0,0,0,0.04); margin-bottom:0;">
            <div class="card-title" style="display:flex; justify-content:space-between; align-items:center;">
                <span style="color:#b45309; font-weight:700; font-size:14px;">⏳ 原型图 2: 智能体初筛 · 待人工复核态势</span>
                <span class="tag tag-medium" style="font-size:11px;">待专家审核</span>
            </div>
            <div style="display:flex; gap:16px; align-items:center; flex-wrap:wrap; margin-top:8px;">
                <div style="position:relative; width:200px; height:200px; flex-shrink:0; display:flex; align-items:center; justify-content:center;">
                    <svg id="pending-donut-svg" width="200" height="200" viewBox="0 0 260 260">
                        <circle cx="130" cy="130" r="56" fill="none" stroke="#f1f5f9" stroke-width="16" />
                    </svg>
                    <div style="position:absolute; text-align:center; pointer-events:none;">
                        <div id="pending-total-count" style="font-size:22px; font-weight:800; color:#b45309; line-height:1;">0</div>
                        <div style="font-size:10.5px; color:#64748b; margin-top:3px;">待人工复核</div>
                    </div>
                </div>
                <div id="pending-stats-box" style="flex:1; min-width:180px; display:grid; grid-template-columns: repeat(auto-fit, minmax(90px, 1fr)); gap:8px;">
                </div>
            </div>
            <div style="font-size:11px; color:#92400e; background:#fffbeb; border:1px solid #fde68a; padding:6px 10px; border-radius:6px; margin-top:10px;">
                💡 智能巡检初筛出的风险线索，点击「🛡️ 确认漏洞」移入左图并从本页划出，或「❌ 标记误报」直接剔除。
            </div>
        </div>
    </div>

    <!-- 🎯 工作台三态分流选项卡 -->
    <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px;">
            <!-- 导航选项卡 -->
            <div class="burp-nav-tabs" style="margin:0; border:none;">
                <button id="tab-btn-pending" class="burp-tab-btn ${currentFindingsWorkflowTab === 'pending' ? 'active' : ''}" onclick="switchFindingsWorkflowTab('pending')">⏳ 待人工审核初筛池 (<span id="tab-cnt-pending">0</span>)</button>
                <button id="tab-btn-confirmed" class="burp-tab-btn ${currentFindingsWorkflowTab === 'confirmed' ? 'active' : ''}" onclick="switchFindingsWorkflowTab('confirmed')">🛡️ 专家已认证实战漏洞库 (<span id="tab-cnt-confirmed">0</span>)</button>
                <button id="tab-btn-trash" class="burp-tab-btn ${currentFindingsWorkflowTab === 'trash' ? 'active' : ''}" onclick="switchFindingsWorkflowTab('trash')">🗑️ 误报与已清除记录 (<span id="tab-cnt-trash">0</span>)</button>
            </div>

            <!-- 极速快捷操作栏 (直接执行，免弹窗打扰) -->
            <div id="workflow-action-toolbar" style="display:flex; gap:8px; flex-wrap:wrap;">
                <!-- 动态填充当前 Tab 的专属操作按钮 -->
            </div>
        </div>

        <div id="findings-table-box">正在加载风险记录...</div>
    </div>

    <!-- 证据链详情模态框 -->
    <div id="evidence-modal" class="modal-overlay">
        <div class="modal-content">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                <h3 id="modal-title" style="color:#0f172a; font-size:16px;">问题详情与现场证据</h3>
                <button onclick="document.getElementById('evidence-modal').style.display='none'" class="btn" style="padding:2px 8px;">✕</button>
            </div>
            <div id="modal-body" style="font-size:13px; line-height:1.6;"></div>
        </div>
    </div>
    `;
}

function filterFindingsByUrl(urlStr) {
    selectedUrlFilter = urlStr;
    const sel = document.getElementById('filter-url');
    if (sel) sel.value = urlStr;
    
    document.querySelectorAll('.url-filter-pill').forEach(pill => {
        if ((!urlStr && pill.innerText.startsWith('全部巡检站点')) || (urlStr && pill.innerText.includes(urlStr))) {
            pill.classList.add('active');
        } else {
            pill.classList.remove('active');
        }
    });

    loadFindingsTable();
}

function renderSingleDonutChart(prefix, findingsList) {
    const svgElem = document.getElementById(`${prefix}-donut-svg`);
    const totalElem = document.getElementById(`${prefix}-total-count`);
    const statsBox = document.getElementById(`${prefix}-stats-box`);
    
    const totalCount = findingsList.length;
    if (totalElem) totalElem.innerText = totalCount;

    const sevCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };
    findingsList.forEach(f => {
        const s = (f.severity || 'INFO').toUpperCase();
        if (sevCounts[s] !== undefined) sevCounts[s]++;
        else sevCounts.INFO++;
    });

    const sevConfig = [
        { key: 'CRITICAL', label: '严重', color: '#dc2626', bg: '#fee2e2', text: '#991b1b', border: '#fca5a5' },
        { key: 'HIGH', label: '高危', color: '#ea580c', bg: '#ffedd5', text: '#9a3412', border: '#fdba74' },
        { key: 'MEDIUM', label: '中危', color: '#d97706', bg: '#fef3c7', text: '#92400e', border: '#fde68a' },
        { key: 'LOW', label: '低危', color: '#2563eb', bg: '#dbeafe', text: '#1e40af', border: '#bfdbfe' },
        { key: 'INFO', label: '提示', color: '#64748b', bg: '#f1f5f9', text: '#334155', border: '#cbd5e1' }
    ];

    if (!svgElem || !statsBox) return;

    if (totalCount === 0) {
        svgElem.innerHTML = `<circle cx="130" cy="130" r="56" fill="none" stroke="#e2e8f0" stroke-width="16" />`;
        statsBox.innerHTML = `<div style="grid-column: 1 / -1; color:#64748b; font-size:12px; padding:10px 0; text-align:center;">暂无匹配记录</div>`;
        return;
    }

    const cx = 130;
    const cy = 130;
    const R = 56;
    const C = 2 * Math.PI * R;
    let offset = 0;
    let circleArcs = '';
    let outerLabels = '';
    let cardsHtml = '';

    sevConfig.forEach(cfg => {
        const count = sevCounts[cfg.key] || 0;
        const percentVal = totalCount > 0 ? ((count / totalCount) * 100).toFixed(1) : 0;
        const percentStr = `${percentVal}%`;

        if (count > 0) {
            const dashLength = (count / totalCount) * C;

            circleArcs += `
            <circle cx="${cx}" cy="${cy}" r="${R}" fill="none" stroke="${cfg.color}" stroke-width="16" 
                    stroke-dasharray="${dashLength.toFixed(2)} ${(C - dashLength).toFixed(2)}" 
                    stroke-dashoffset="${(-offset).toFixed(2)}"
                    style="transition: all 0.5s ease; cursor:pointer;"
                    onclick="quickFilterSeverity('${cfg.key}')">
                <title>${cfg.label}: ${count} 处 (${percentStr}) - 点击筛选</title>
            </circle>
            `;

            const startDeg = (offset / C) * 360 - 90;
            const spanDeg = (dashLength / C) * 360;
            const midDeg = startDeg + spanDeg / 2;
            const rad = midDeg * Math.PI / 180;

            const rStart = R + 10;
            const x1 = cx + rStart * Math.cos(rad);
            const y1 = cy + rStart * Math.sin(rad);

            const rLabel = R + 38;
            const x2 = cx + rLabel * Math.cos(rad);
            const y2 = cy + rLabel * Math.sin(rad);

            const badgeW = percentStr.length * 7.5 + 8;

            outerLabels += `
            <g style="cursor:pointer;" onclick="quickFilterSeverity('${cfg.key}')" title="${cfg.label}: ${count} 处 (${percentStr})">
                <line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" 
                      stroke="${cfg.color}" stroke-width="1.2" stroke-dasharray="2,2" opacity="0.85" />
                <rect x="${(x2 - badgeW / 2).toFixed(1)}" y="${(y2 - 9).toFixed(1)}" width="${badgeW}" height="18" rx="4" 
                      fill="${cfg.bg}" stroke="${cfg.color}" stroke-width="1" />
                <text x="${x2.toFixed(1)}" y="${(y2 + 3.8).toFixed(1)}" text-anchor="middle" font-size="10" font-weight="800" fill="${cfg.text}">
                    ${percentStr}
                </text>
            </g>
            `;

            offset += dashLength;
        }

        cardsHtml += `
        <div onclick="quickFilterSeverity('${cfg.key}')" 
             style="background:#ffffff; border:1px solid ${count > 0 ? cfg.border : '#e2e8f0'}; border-radius:8px; padding:6px 8px; cursor:pointer; transition:all 0.2s ease;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:11px; font-weight:700; color:${cfg.color};">${cfg.label}</span>
                <span style="font-size:10px; color:#64748b;">${percentStr}</span>
            </div>
            <div style="display:flex; align-items:baseline; gap:2px; margin-top:2px;">
                <span style="font-size:15px; font-weight:800; color:${cfg.text};">${count}</span>
                <span style="font-size:10px; color:#64748b;">处</span>
            </div>
        </div>
        `;
    });

    svgElem.innerHTML = `
    <g transform="rotate(-90 ${cx} ${cy})">
        ${circleArcs}
    </g>
    <g>
        ${outerLabels}
    </g>
    `;
    statsBox.innerHTML = cardsHtml;
}

window.quickFilterSeverity = function(sevKey) {
    const sel = document.getElementById('filter-sev');
    if (!sel) return;
    if (sel.value === sevKey) {
        sel.value = '';
    } else {
        sel.value = sevKey;
    }
    loadFindingsTable();
};

async function loadFindingsTable() {
    const cat = document.getElementById('filter-cat')?.value || '';
    const sev = document.getElementById('filter-sev')?.value || '';
    const srcFilter = document.getElementById('filter-src')?.value || '';

    let url = `${API_BASE}/findings?`;
    if (cat) url += `category=${cat}&`;
    if (sev) url += `severity=${sev}&`;

    try {
        const res = await fetch(url);
        let allFindings = await res.json();
        const box = document.getElementById('findings-table-box');
        if (!box) return;

        // 🎯 应用 SRC 漏洞收录标准过滤
        if (srcFilter) {
            allFindings = allFindings.filter(f => {
                const titleLower = (f.title || '').toLowerCase();
                const isSrcExploitable = f.src_type === 'SRC_EXPLOITABLE' || [
                    'sql', '注入', 'sqli', 'ssti', '模板', '命令注入', 'command', 'rce', '代码执行',
                    '文件读取', '路径穿越', 'lfi', 'path traversal', 'bola', 'idor', '越权', '未授权',
                    'xss', '跨站脚本', 'ssrf', '请求伪造', '挖矿', '后门', '暗链', '篡改', '涂鸦', 'defacement',
                    'coinhive', 'eval(', '.env', 'backup.sql', '.git', '身份证', '银行卡', 'accesskey',
                    '数据库连接串', 'jwt', 'cors', '跨域'
                ].some(k => titleLower.includes(k));
                
                if (srcFilter === 'SRC_EXPLOITABLE') return isSrcExploitable;
                if (srcFilter === 'BASELINE_HYGIENE') return !isSrcExploitable;
                return true;
            });
        }

        // 按巡检主网址 (Target Root URL) 进行归类统计
        const rootSiteCounts = {};
        allFindings.forEach(f => {
            const rootSite = extractRootSiteUrl(f.url);
            rootSiteCounts[rootSite] = (rootSiteCounts[rootSite] || 0) + 1;
        });

        // 填充主网址下拉选择框与标签栏
        const urlSelect = document.getElementById('filter-url');
        const urlPillsBox = document.getElementById('url-pills-box');
        if (urlSelect && urlSelect.options.length <= 1) {
            let selectOptionsHtml = '<option value="">全部巡检站点 (全部资产)</option>';
            let pillsHtml = `<span style="font-size:12px; font-weight:700; color:#0f172a; margin-right:4px;">🌐 巡检主网址分类：</span>
                <button class="url-filter-pill ${!selectedUrlFilter ? 'active' : ''}" onclick="filterFindingsByUrl('')">全部巡检站点 (${allFindings.length})</button>`;
            
            for (const [rSite, count] of Object.entries(rootSiteCounts)) {
                selectOptionsHtml += `<option value="${escapeHtml(rSite)}" ${selectedUrlFilter === rSite ? 'selected' : ''}>${escapeHtml(rSite)} (共 ${count} 处问题)</option>`;
                pillsHtml += `<button class="url-filter-pill ${selectedUrlFilter === rSite ? 'active' : ''}" onclick="filterFindingsByUrl(${safeInlineArg(rSite)})"><code>${escapeHtml(rSite)}</code> <span class="tag tag-critical" style="font-size:10px; padding:0 5px;">${count}</span></button>`;
            }
            urlSelect.innerHTML = selectOptionsHtml;
            if (urlPillsBox) urlPillsBox.innerHTML = pillsHtml;
        }

        // 应用巡检主网址过滤
        let findings = allFindings;
        if (selectedUrlFilter) {
            findings = allFindings.filter(f => extractRootSiteUrl(f.url) === selectedUrlFilter || f.url.startsWith(selectedUrlFilter));
        }

        // 🎯 核心分流：分为【待审核初筛池】、【专家已认证库】、【误报与已清除记录】
        const confirmedList = findings.filter(f => f.status === 'CONFIRMED');
        const pendingList = findings.filter(f => f.status === 'OPEN');
        const trashList = findings.filter(f => f.status === 'FALSE_POSITIVE' || f.status === 'IGNORED');

        // 实时更新两座原型图
        renderSingleDonutChart('confirmed', confirmedList);
        renderSingleDonutChart('pending', pendingList);

        // 更新 3 个 Tab 的数量徽章
        const pCntElem = document.getElementById('tab-cnt-pending');
        const cCntElem = document.getElementById('tab-cnt-confirmed');
        const tCntElem = document.getElementById('tab-cnt-trash');
        if (pCntElem) pCntElem.innerText = pendingList.length;
        if (cCntElem) cCntElem.innerText = confirmedList.length;
        if (tCntElem) tCntElem.innerText = trashList.length;

        // 根据当前选中的 Tab 决定展示哪部分漏洞
        let currentDisplayList = [];
        let toolbarHtml = '';

        if (currentFindingsWorkflowTab === 'pending') {
            currentDisplayList = pendingList;
            toolbarHtml = `
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#f0fdf4; color:#15803d; border-color:#bbf7d0; font-weight:700;" onclick="batchConfirmSelected()">✔ 批量确认选中项</button>
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#fffbeb; color:#b45309; border-color:#fde68a;" onclick="batchFalsePositiveSelected()">❌ 批量标记为误报</button>
                <span style="border-left:1px solid #cbd5e1; margin:0 4px;"></span>
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#f0fdf4; color:#15803d; border-color:#bbf7d0;" onclick="batchConfirmCriticalFindingsDirect()">🛡️ 一键确认所有严重/高危漏洞</button>
                <button class="btn" style="font-size:11px; padding:3px 10px; color:#dc2626;" onclick="batchClearFalsePositivesDirect()">❌ 一键排除当前初筛为误报</button>
                <button class="btn" style="font-size:11px; padding:3px 10px;" onclick="loadFindingsTable()">🔄 刷新列表</button>
            `;
        } else if (currentFindingsWorkflowTab === 'confirmed') {
            currentDisplayList = confirmedList;
            toolbarHtml = `
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#fffbeb; color:#b45309; border-color:#fde68a;" onclick="batchFalsePositiveSelected()">↩️ 批量移出为误报</button>
                <span style="border-left:1px solid #cbd5e1; margin:0 4px;"></span>
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#e0f2fe; color:#0369a1; border-color:#bae6fd;" onclick="window.print()">📄 导出已认证漏洞清单</button>
                <button class="btn" style="font-size:11px; padding:3px 10px;" onclick="loadFindingsTable()">🔄 刷新列表</button>
            `;
        } else {
            currentDisplayList = trashList;
            toolbarHtml = `
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#f0f9ff; color:#0284c7; border-color:#bae6fd;" onclick="batchConfirmSelected()">↩️ 批量还原为待审记录 (通过接口实现)</button>
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#fee2e2; color:#991b1b; border-color:#fca5a5; font-weight:700;" onclick="batchDeleteSelected()">🗑️ 批量彻底删除选中项</button>
                <span style="border-left:1px solid #cbd5e1; margin:0 4px;"></span>
                <button class="btn" style="font-size:11px; padding:3px 10px; background:#fee2e2; color:#991b1b; border-color:#fca5a5; font-weight:700;" onclick="cleanupAllFalsePositivesDirect()">💥 一键清空所有误报 (彻底删除)</button>
                <button class="btn" style="font-size:11px; padding:3px 10px;" onclick="loadFindingsTable()">🔄 刷新列表</button>
            `;
        }

        const toolbarBox = document.getElementById('workflow-action-toolbar');
        if (toolbarBox) toolbarBox.innerHTML = toolbarHtml;

        if (currentDisplayList.length === 0) {
            let emptyMsg = '当前初筛池中已无待审核漏洞';
            if (currentFindingsWorkflowTab === 'confirmed') emptyMsg = '暂无专家已认证漏洞，请在「待审核池」中点击【🛡️ 确认漏洞】添加';
            if (currentFindingsWorkflowTab === 'trash') emptyMsg = '回收站暂无误报记录';
            box.innerHTML = `<p style="color:#166534; padding:30px 0; text-align:center; font-size:13px;">🎉 ${emptyMsg}</p>`;
            return;
        }

        let html = `<table class="data-table">
            <thead>
                <tr>
                    <th style="width:30px; text-align:center;"><input type="checkbox" id="selectAllFindings" onclick="toggleSelectAllFindings(this.checked)" title="全选当前列表所有记录"></th>
                    <th>严重级别</th>
                    <th>标准定级</th>
                    <th>审核状态</th>
                    <th>类别</th>
                    <th>问题名称</th>
                    <th>归属主站与发现的子资产</th>
                    <th>评分</th>
                    <th>快捷流转操作 (免弹窗即时生效)</th>
                </tr>
            </thead>
            <tbody>`;
        currentDisplayList.forEach(f => {
            const sevTag = f.severity.toLowerCase();
            const rootSite = extractRootSiteUrl(f.url);
            const titleLower = (f.title || '').toLowerCase();
            const isSrcExploitable = f.src_type === 'SRC_EXPLOITABLE' || [
                'sql', '注入', 'sqli', 'ssti', '模板', '命令注入', 'command', 'rce', '代码执行',
                '文件读取', '路径穿越', 'lfi', 'path traversal', 'bola', 'idor', '越权', '未授权',
                'xss', '跨站脚本', 'ssrf', '请求伪造', '挖矿', '后门', '暗链', '篡改', '涂鸦', 'defacement',
                'coinhive', 'eval(', '.env', 'backup.sql', '.git', '身份证', '银行卡', 'accesskey',
                '数据库连接串', 'jwt', 'cors', '跨域'
            ].some(k => titleLower.includes(k));

            let sevCn = '提示';
            if (f.severity === 'CRITICAL') sevCn = '严重';
            else if (f.severity === 'HIGH') sevCn = '高危';
            else if (f.severity === 'MEDIUM') sevCn = '中危';
            else if (f.severity === 'LOW') sevCn = '低危';

            let subPath = '/';
            try {
                const u = new URL(f.url);
                subPath = u.pathname + u.search;
            } catch(e) {
                subPath = f.url;
            }

            // 状态标签
            let statusBadgeHtml = '';
            if (f.status === 'CONFIRMED') {
                statusBadgeHtml = `<span class="tag tag-low" style="background:#dcfce7; color:#15803d; border:1px solid #86efac; font-weight:700;">🛡️ 人工已确认</span>`;
            } else if (f.status === 'FALSE_POSITIVE' || f.status === 'IGNORED') {
                statusBadgeHtml = `<span class="tag" style="background:#f1f5f9; color:#94a3b8; text-decoration:line-through; font-size:11px;">❌ 误报/已排除</span>`;
            } else if (f.status === 'FIXED') {
                statusBadgeHtml = `<span class="tag tag-low">✔ 已修复</span>`;
            } else {
                statusBadgeHtml = `<span class="tag tag-medium" style="background:#fffbeb; color:#b45309; border:1px solid #fde68a; font-weight:600;">⏳ 待人工审核</span>`;
            }

            // 流转操作按钮 (直接执行，免任何弹窗确认！)
            let actionBtnsHtml = '';
            if (f.status === 'CONFIRMED') {
                actionBtnsHtml = `
                    <button class="btn" style="font-size:11px; padding:3px 8px; color:#b45309; border-color:#fde68a;" onclick="setFindingStatusDirect(${safeInlineArg(f.id)}, 'OPEN')" title="撤回认证，移回待审池">↩️ 移回待审</button>
                    <button class="btn" style="font-size:11px; padding:3px 8px; color:#dc2626; border-color:#fca5a5;" onclick="setFindingStatusDirect(${safeInlineArg(f.id)}, 'FALSE_POSITIVE')" title="移出并标记为误报">❌ 移入误报</button>
                `;
            } else if (f.status === 'FALSE_POSITIVE' || f.status === 'IGNORED') {
                actionBtnsHtml = `
                    <button class="btn" style="font-size:11px; padding:3px 8px; color:#0284c7;" onclick="setFindingStatusDirect(${safeInlineArg(f.id)}, 'OPEN')" title="重新纳入待审核初筛池">↩️ 重新入池</button>
                    <button class="btn" style="font-size:11px; padding:3px 8px; color:#dc2626; border-color:#fca5a5;" onclick="deleteFindingDirect(${safeInlineArg(f.id)})" title="从数据库彻底删除">🗑️ 彻底删除</button>
                `;
            } else {
                actionBtnsHtml = `
                    <button class="btn btn-primary" style="font-size:11px; padding:3px 9px; background:#16a34a; border-color:#15803d; font-weight:700;" onclick="setFindingStatusDirect(${safeInlineArg(f.id)}, 'CONFIRMED')" title="人工复核通过：移入已认证实战库，并从本页划出">🛡️ 确认漏洞</button>
                    <button class="btn" style="font-size:11px; padding:3px 8px; color:#dc2626; border-color:#fca5a5;" onclick="setFindingStatusDirect(${safeInlineArg(f.id)}, 'FALSE_POSITIVE')" title="标记为误报并从本页划出">❌ 标记误报</button>
                `;
            }

            html += `<tr>
                <td style="text-align:center;"><input type="checkbox" class="finding-row-checkbox" value="${escapeHtml(f.id)}" ${window.selectedFindingIds && window.selectedFindingIds.has(f.id) ? 'checked' : ''} onclick="toggleSingleFinding(${safeInlineArg(f.id)}, this.checked)"></td>
                <td><span class="tag tag-${sevTag}" style="font-weight:700; font-size:11px; padding:2px 8px;">${sevCn}</span></td>
                <td><span class="tag tag-${isSrcExploitable ? 'critical' : 'info'}" style="font-size:10.5px; padding:1px 6px;">${isSrcExploitable ? '🎯 SRC 实战漏洞' : '📋 安全基线建议'}</span></td>
                <td>${statusBadgeHtml}</td>
                <td><span style="font-size:11px; color:#64748b;">${escapeHtml(f.category)}</span></td>
                <td><strong>${escapeHtml(f.title)}</strong></td>

                <td>
                    <div style="font-weight:700; color:#0f172a; font-size:12px;">🏠 ${escapeHtml(rootSite)}</div>
                    <div style="margin-top:3px;">
                        <span class="tag" style="background:#e0f2fe; color:#0369a1; font-size:11px; padding:1px 6px; border:1px solid #bae6fd;">
                            📂 子资产: <code>${escapeHtml(subPath)}</code>
                        </span>
                    </div>
                </td>
                <td><strong>${escapeHtml(f.cvss_score)}</strong></td>
                <td>
                    <div style="display:flex; gap:4px; flex-wrap:wrap; align-items:center;">
                        ${actionBtnsHtml}
                        <button class="btn" style="font-size:11px; padding:3px 6px;" onclick="showEvidence(${safeInlineArg(f.id)})">🔍 证据</button>
                        <button class="btn" style="font-size:11px; padding:3px 6px;" onclick="openTaskDetailsView(${safeInlineArg(f.task_id)}, ${safeInlineArg(f.url)}, ${safeInlineArg(f.id)})" title="查看网页拓扑图与该页漏洞">⚡ 拓扑</button>
                    </div>
                </td>
            </tr>`;
        });
        html += `</tbody></table>`;
        box.innerHTML = html;
    } catch (e) {
        console.error(e);
    }
}

async function showEvidence(id) {
    const res = await fetch(`${API_BASE}/findings/${id}`);
    const f = await res.json();
    
    document.getElementById('modal-title').innerText = `[${f.severity}] ${f.title}`;
    const evidence = f.evidence || {};
    const deep = f.deep_audit || (typeof evidence.deep_audit === 'object' ? evidence.deep_audit : null);
    
    let deepAuditHtml = '';
    if (deep) {
        let deepDetailContent = '';
        if (deep.findings_detail) {
            deepDetailContent = `<pre style="background:#0f172a; color:#38bdf8; padding:10px; border-radius:6px; font-size:11px; overflow-x:auto;">${escapeHtml(JSON.stringify(deep.findings_detail, null, 2))}</pre>`;
        } else if (deep.accessible_files) {
            let fileListHtml = deep.accessible_files.map(af => `
                <li style="margin-bottom:4px;">
                    <code style="color:#dc2626; font-weight:bold;">${escapeHtml(af.file)}</code> - <span>${escapeHtml(af.description)}</span>
                    <div style="color:#64748b; font-size:11px; margin-top:2px;">摘要: <code>${escapeHtml(af.sample_snippet)}</code></div>
                </li>
            `).join('');
            deepDetailContent = `<ul style="padding-left:18px; margin-top:6px; font-size:12px;">${fileListHtml}</ul>`;
        } else if (deep.enumeration_proof) {
            let enumRows = deep.enumeration_proof.map(ep => `
                <tr>
                    <td><code>ID: ${escapeHtml(ep.object_id)}</code></td>
                    <td><span class="tag tag-high">可越权读取</span></td>
                    <td><code style="font-size:11px;">${escapeHtml(ep.response_preview)}</code></td>
                </tr>
            `).join('');
            deepDetailContent = `
                <table class="data-table" style="font-size:11px; margin-top:6px;">
                    <thead><tr><th>探测对象 ID</th><th>越权状态</th><th>泄露敏感数据摘要</th></tr></thead>
                    <tbody>${enumRows}</tbody>
                </table>
            `;
        }

        let diffPatchHtml = '';
        if (deep.remediation_patch_diff) {
            diffPatchHtml = `
            <div style="margin-top:10px;">
                <div style="font-weight:bold; font-size:12px; color:#15803d; margin-bottom:4px;">📋 官方级代码修复建议 (Unified Diff Patch)：</div>
                <pre style="background:#1e293b; color:#4ade80; padding:10px; border-radius:6px; font-size:11px; font-family:monospace; overflow-x:auto;">${escapeHtml(deep.remediation_patch_diff)}</pre>
            </div>
            `;
        }

        deepAuditHtml = `
        <div style="background:#f0fdfa; border:1px solid #99f6e4; border-radius:8px; padding:12px 14px; margin:14px 0;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:#0d9488; font-size:13px;">🚀 专项深入利用测试证据 (Specialized Post-Discovery Deep Audit)</strong>
                <span class="tag ${f.verified ? 'tag-low' : 'tag-medium'}" style="font-size:10px;">${f.verified ? '已获得复核证据' : '待人工复核'}</span>
            </div>
            <div style="font-size:12px; color:#134e4a; margin-top:6px;">
                <strong>所属专项分析模块：</strong> ${escapeHtml(deep.specialized_module || '专项证据分析模块')}
            </div>
            <div style="margin-top:8px;">
                ${deepDetailContent}
            </div>
            ${diffPatchHtml}
        </div>
        `;
    }

    let bodyHtml = `
    <p><strong>📍 出现问题的网址：</strong> <code style="color:#0284c7;">${escapeHtml(f.url)}</code></p>
    <p style="margin-top:6px;"><strong>⚠️ 危害与风险说明：</strong> ${escapeHtml(f.impact)}</p>
    
    ${deepAuditHtml}

    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px; margin:14px 0;">
        <strong style="color:#0284c7;">🔍 现场抓到的证据 (Evidence Snapshot):</strong>
        <pre style="color:#0f172a; font-family:monospace; margin-top:8px; white-space:pre-wrap; word-break:break-all; font-size:12px;">${escapeHtml(evidence.matched_snippet || JSON.stringify(evidence, null, 2))}</pre>
    </div>

    <div style="background:#f0fdf4; border-left:4px solid #16a34a; padding:10px 14px; border-radius:4px; margin-top:12px;">
        <strong style="color:#15803d;">🛠️ 修复方法 (照着改就能修好)：</strong>
        <p style="margin-top:4px; color:#166534;">${escapeHtml(f.remediation)}</p>
    </div>

    <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:16px;">
        <button class="btn btn-primary" onclick="retestSingleFindingLive(${safeInlineArg(f.id)})">⚡ 立即重新检查是否修好</button>
        <button class="btn" onclick="updateFindingStatus(${safeInlineArg(f.id)}, ${safeInlineArg(f.status === 'OPEN' ? 'FIXED' : 'OPEN')})">
            ${f.status === 'OPEN' ? '✔ 手动标记为已修复' : '重新标记为待处理'}
        </button>
    </div>
    `;
    
    document.getElementById('modal-body').innerHTML = bodyHtml;
    document.getElementById('evidence-modal').style.display = 'flex';
}


async function updateFindingStatus(id, newStatus) {
    await fetch(`${API_BASE}/findings/${id}/status?status=${newStatus}`, { method: 'POST' });
    if (currentDetailTaskId) {
        refreshTaskDetailsLive();
    } else {
        loadFindingsTable();
    }
}

/* ---------------- 5. BASELINE ---------------- */
function getBaselineHTML() {
    return `
    <div class="card" style="margin-bottom:20px;">
        <div class="card-title"><span>⚖️ 对比两次巡检结果 (看看修好了什么、新出现了什么)</span></div>
        <div class="grid-2">
            <div class="form-group">
                <label class="form-label">基准任务 (前一次检查)</label>
                <select id="base-task-select" class="form-select"></select>
            </div>
            <div class="form-group">
                <label class="form-label">对比任务 (本次最新检查)</label>
                <select id="curr-task-select" class="form-select"></select>
            </div>
        </div>
        <button class="btn btn-primary" onclick="runBaselineDiff()">开始对比差异</button>
    </div>

    <div class="card" id="baseline-diff-result" style="display:none;">
        <div class="card-title"><span>📊 对比分析结果</span></div>
        <div id="diff-content"></div>
    </div>
    `;
}

async function loadBaselineOptions() {
    const res = await fetch(`${API_BASE}/tasks`);
    const tasks = await res.json();
    const baseSel = document.getElementById('base-task-select');
    const currSel = document.getElementById('curr-task-select');
    if (!baseSel || !currSel) return;

    let opts = tasks.map(t => `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)} (${escapeHtml((t.created_at || '').substring(0, 19))})</option>`).join('');
    baseSel.innerHTML = opts;
    currSel.innerHTML = opts;
    if (tasks.length > 1) {
        currSel.selectedIndex = 0;
        baseSel.selectedIndex = 1;
    }
}

async function runBaselineDiff() {
    const baseId = document.getElementById('base-task-select').value;
    const currId = document.getElementById('curr-task-select').value;
    if (!baseId || !currId) return alert('请选择需要对比的两个巡检任务');

    try {
        const res = await fetch(`${API_BASE}/baselines/compare?base_task_id=${baseId}&current_task_id=${currId}`);
        const diff = await res.json();

        document.getElementById('baseline-diff-result').style.display = 'block';
        const box = document.getElementById('diff-content');

        let html = `
        <div class="grid-4" style="margin-bottom:16px;">
            <div class="card" style="background:#f8fafc;">
                <div class="card-title">整体安全趋势</div>
                <div class="card-val" style="font-size:18px; color:#16a34a;">${escapeHtml(diff.risk_trend)}</div>
            </div>
            <div class="card" style="background:#f8fafc;">
                <div class="card-title">已修复好隐患</div>
                <div class="card-val" style="font-size:18px; color:#16a34a;">+${diff.fixed_findings_count} 项</div>
            </div>
            <div class="card" style="background:#f8fafc;">
                <div class="card-title">新出现的问题</div>
                <div class="card-val" style="font-size:18px; color:#dc2626;">${diff.new_findings_count} 项</div>
            </div>
            <div class="card" style="background:#f8fafc;">
                <div class="card-title">网页内容变动</div>
                <div class="card-val" style="font-size:18px; color:#d97706;">${diff.tampered_pages_count} 处</div>
            </div>
        </div>

        <h4 style="color:#16a34a; margin:16px 0 8px 0;">🎉 本次巡检已成功修好闭环的问题 (${diff.fixed_findings_count} 项):</h4>
        ${diff.fixed_findings.length ? diff.fixed_findings.map(f => `<p style="color:#15803d; font-size:13px; margin-bottom:4px;">✔ [已修复] <strong>${escapeHtml(f.title)}</strong> (${escapeHtml(f.url)})</p>`).join('') : '<p style="color:#64748b; font-size:13px;">无</p>'}

        <h4 style="color:#dc2626; margin:16px 0 8px 0;">⚠️ 本次巡检新出现的问题 (${diff.new_findings_count} 项):</h4>
        ${diff.new_findings.length ? diff.new_findings.map(f => `<p style="color:#dc2626; font-size:13px; margin-bottom:4px;">✖ [新风险] <strong>${escapeHtml(f.title)}</strong> (${escapeHtml(f.url)})</p>`).join('') : '<p style="color:#64748b; font-size:13px;">无新增隐患</p>'}
        `;
        box.innerHTML = html;
    } catch (e) {
        alert('基线对比失败: ' + e);
    }
}

/* ---------------- 6. SENSITIVE RULES ---------------- */
function getRulesHTML() {
    return `
    <div class="grid-2">
        <div class="card">
            <div class="card-title"><span>➕ 添加自定义敏感信息规则 (防泄露)</span></div>
            <div class="form-group">
                <label class="form-label">快速选择常用模板</label>
                <select class="form-select" onchange="applyRuleTemplate(this.value)">
                    <option value="">-- 点击选择常用模板一键填充 --</option>
                    <option value="idcard">中华人民共和国居民二代身份证 (带 18 位算法真伪校验)</option>
                    <option value="phone">中国大陆 11 位手机号</option>
                    <option value="bankcard">银联与各银行卡号 (Luhn 校验算法)</option>
                    <option value="aksk">云平台 AccessKey 凭证 (阿里云/腾讯云)</option>
                    <option value="dbconn">数据库连接账号与密码泄露</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">规则名称</label>
                <input type="text" id="rule-name" class="form-input" placeholder="例如：核心业务机密工单代号">
            </div>
            <div class="form-group">
                <label class="form-label">规则类型</label>
                <select id="rule-category" class="form-select">
                    <option value="CUSTOM_REGEX">自定义正则表达式 (CUSTOM_REGEX)</option>
                    <option value="KEYWORD">敏感关键词匹配 (KEYWORD)</option>
                    <option value="SECRET_KEY">应用秘钥/Token (SECRET_KEY)</option>
                    <option value="FILE_TYPE">敏感文件类型 (FILE_TYPE)</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">匹配规则模式 (正则或关键词)</label>
                <input type="text" id="rule-pattern" class="form-input" placeholder="例如：SEC-PROJ-[A-Z0-9]{6}">
            </div>
            <div class="form-group">
                <label class="form-label">危险等级</label>
                <select id="rule-risk" class="form-select">
                    <option value="CRITICAL">严重 (Critical)</option>
                    <option value="HIGH" selected>高危 (High)</option>
                    <option value="MEDIUM">中危 (Medium)</option>
                    <option value="LOW">低危 (Low)</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="createRule()">保存此规则</button>
        </div>

        <div class="card">
            <div class="card-title"><span>🧪 在线测试沙箱 (实时看匹配和脱敏效果)</span></div>
            <div class="form-group">
                <label class="form-label">粘贴一段测试文字</label>
                <textarea id="test-sample-text" class="form-textarea" rows="5" placeholder="粘贴一段包含身份证、电话或自定义数据的文本进行匹配测试..."></textarea>
            </div>
            <button class="btn btn-primary" onclick="testRulePattern()">立即测试匹配</button>
            <div id="rule-test-result" style="margin-top:12px; font-size:12px;"></div>
        </div>
    </div>

    <div class="card">
        <div class="card-title"><span>🔒 敏感信息规则库清单</span></div>
        <div id="rules-table-box">正在加载规则...</div>
    </div>
    `;
}

function applyRuleTemplate(tpl) {
    if (!tpl) return;
    const name = document.getElementById('rule-name');
    const cat = document.getElementById('rule-category');
    const pat = document.getElementById('rule-pattern');
    const risk = document.getElementById('rule-risk');
    const sample = document.getElementById('test-sample-text');

    if (tpl === 'idcard') {
        name.value = '中华人民共和国居民身份证';
        cat.value = 'CUSTOM_REGEX';
        pat.value = '(?<!\\d)[1-9]\\d{5}(?:18|19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx](?!\\d)';
        risk.value = 'HIGH';
        sample.value = '测试公民信息：张三，身份证号 110101199003072379，联系电话 13800138000。';
    } else if (tpl === 'phone') {
        name.value = '中国大陆11位手机号';
        cat.value = 'CUSTOM_REGEX';
        pat.value = '(?<!\\d)(?:\\+?86)?1[3-9]\\d{9}(?!\\d)';
        risk.value = 'MEDIUM';
        sample.value = '紧急联系人电话：13912345678 或 +8613800000000。';
    } else if (tpl === 'bankcard') {
        name.value = '银联借记卡与信用卡号';
        cat.value = 'CUSTOM_REGEX';
        pat.value = '(?<!\\d)(?:4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|62\\d{14,17}|3[47]\\d{13})(?!\\d)';
        risk.value = 'CRITICAL';
        sample.value = '报销收款卡号：6222021234567890123。';
    } else if (tpl === 'aksk') {
        name.value = '阿里云/腾讯云 AccessKey ID 凭证';
        cat.value = 'SECRET_KEY';
        pat.value = '(?<![A-Za-z0-9])(?:LTAI[A-Za-z0-9]{16,20}|AKID[A-Za-z0-9]{16,32})(?![A-Za-z0-9])';
        risk.value = 'CRITICAL';
        sample.value = 'config.oss.access_key_id = "LTAI5t7XYZ1234567890";';
    } else if (tpl === 'dbconn') {
        name.value = '数据库连接密码暴露';
        cat.value = 'SECRET_KEY';
        pat.value = '(?i)(?:mysql|postgresql|mongodb)://[a-zA-Z0-9_-]+:[^@\\s]+@[a-zA-Z0-9.-]+:\\d+';
        risk.value = 'CRITICAL';
        sample.value = 'DATABASE_URL="mysql://root:P@ssw0rd2026@10.0.0.5:3306/prod_db";';
    }
}

async function loadRulesTable() {
    try {
        const res = await fetch(`${API_BASE}/rules`);
        const rules = await res.json();
        const box = document.getElementById('rules-table-box');
        if (!box) return;

        let html = `<table class="data-table">
            <thead>
                <tr>
                    <th>规则名称</th>
                    <th>分类</th>
                    <th>危险等级</th>
                    <th>规则匹配模式</th>
                    <th>规则属性</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody>`;
        rules.forEach(r => {
            html += `<tr>
                <td><strong>${escapeHtml(r.name)}</strong></td>
                <td><code>${escapeHtml(r.category)}</code></td>
                <td><span class="tag tag-${escapeHtml(r.risk_level.toLowerCase())}">${escapeHtml(r.risk_level)}</span></td>
                <td><code style="color:#0284c7;">${escapeHtml(r.pattern.substring(0, 45))}${r.pattern.length > 45 ? '...' : ''}</code></td>
                <td>${r.is_builtin ? '<span class="tag tag-info">系统内置</span>' : '<span class="tag tag-medium">用户自定义</span>'}</td>
                <td>
                    ${!r.is_builtin ? `<button class="btn" style="font-size:11px; color:#dc2626; padding:2px 6px;" onclick="deleteRule(${safeInlineArg(r.id)})">删除</button>` : '<span style="color:#64748b; font-size:11px;">内置保护</span>'}
                </td>
            </tr>`;
        });
        html += `</tbody></table>`;
        box.innerHTML = html;
    } catch (e) {
        console.error(e);
    }
}

async function createRule() {
    const name = document.getElementById('rule-name').value.trim();
    const cat = document.getElementById('rule-category').value;
    const pattern = document.getElementById('rule-pattern').value.trim();
    const risk = document.getElementById('rule-risk').value;

    if (!name || !pattern) return alert('请填写规则名称与模式');

    try {
        await fetch(`${API_BASE}/rules`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                name: name,
                category: cat,
                pattern: pattern,
                risk_level: risk
            })
        });
        alert('规则保存成功！');
        loadRulesTable();
    } catch (e) {
        alert('保存失败: ' + e);
    }
}

async function testRulePattern() {
    const pattern = document.getElementById('rule-pattern')?.value.trim() || "(?<!\\d)[1-9]\\d{5}(?:18|19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[\\dXx](?!\\d)";
    const cat = document.getElementById('rule-category')?.value || 'ID_CARD';
    const text = document.getElementById('test-sample-text').value;

    if (!text) return alert('请输入测试文本');

    const res = await fetch(`${API_BASE}/rules/test`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ pattern: pattern, category: cat, test_text: text })
    });
    const data = await res.json();
    const resultBox = document.getElementById('rule-test-result');
    if (data.success) {
        resultBox.innerHTML = `<p style="color:#16a34a; font-weight:600;">✔ 成功抓到敏感数据！共命中 <strong>${escapeHtml(data.match_count)}</strong> 处：</p>
        ${data.matches.map(m => `<div style="background:#f8fafc; border:1px solid #e2e8f0; padding:8px 12px; border-radius:4px; margin-top:4px;">
            原值: <code>${escapeHtml(m.value)}</code> | 自动脱敏掩码: <strong style="color:#0284c7;">${escapeHtml(m.masked)}</strong> | 算法校验真假: ${m.is_valid_checksum ? '✅ 是有效真实号码' : '❌ 假号码或误报过滤(系统会自动过滤)'}
        </div>`).join('')}`;
    } else {
        resultBox.innerHTML = `<p style="color:#dc2626;">❌ 测试错误: ${escapeHtml(data.error)}</p>`;
    }
}

async function deleteRule(id) {
    if (!confirm('确定删除该规则吗？')) return;
    await fetch(`${API_BASE}/rules/${id}`, { method: 'DELETE' });
    loadRulesTable();
}

/* ---------------- 7. HENGNAO PLATFORM ---------------- */
function getHengnaoHTML() {
    return `
    <div class="grid-2">
        <div class="card">
            <div class="card-title"><span>🤖 安恒恒脑安全智能体开发平台 (gc.das-ai.com) 对接</span></div>
            <p style="font-size:13px; color:#64748b; margin-bottom:12px;">平台对接不在本轮功能优化范围内；以下内容仅保留为后续集成占位，不代表当前已完成联调。</p>
            <div style="background:#f8fafc; padding:14px; border-radius:8px; border:1px solid #e2e8f0; font-size:13px;">
                <p><strong>恒脑平台地址：</strong> <code>https://gc.das-ai.com/</code></p>
                <p style="margin-top:6px;"><strong>智能体标识：</strong> <code>agent-das-websec-inspector</code></p>
                <p style="margin-top:6px;"><strong>工具清单规范：</strong> OpenAPI 3.0 / Function Calling Schema</p>
                <p style="margin-top:6px;"><strong>当前对接状态：</strong> <span class="badge-pill" style="display:inline-flex; background:#fef3c7; color:#92400e; border-color:#fde68a;">未启用 / 未联调</span></p>
            </div>
        </div>

        <div class="card">
            <div class="card-title"><span>📋 恒脑 Tool Manifest 注册清单预览</span></div>
            <pre id="hengnao-json" style="background:#f8fafc; border:1px solid #e2e8f0; padding:12px; border-radius:8px; font-size:12px; color:#0f172a; height:260px; overflow:auto;"></pre>
        </div>
    </div>
    `;
}

async function loadHengnaoManifest() {
    const res = await fetch(`${API_BASE}/agent/tools`);
    const data = await res.json();
    const box = document.getElementById('hengnao-json');
    if (box) box.innerText = JSON.stringify(data, null, 2);
}

/* ---------------- 8. AUDIT LOGS ---------------- */
function getAuditHTML() {
    return `
    <div class="card">
        <div class="card-title"><span>📜 安全操作审计日志 (非破坏性与权限留痕)</span></div>
        <div id="audit-table-box">正在加载审计记录...</div>
    </div>
    `;
}

async function loadAuditLogs() {
    try {
        const res = await fetch(`${API_BASE}/reports/audit-logs?limit=50`);
        const logs = await res.json();
        const box = document.getElementById('audit-table-box');
        if (!box) return;

        let html = `<table class="data-table">
            <thead>
                <tr>
                    <th>时间戳</th>
                    <th>操作动作</th>
                    <th>操作主体</th>
                    <th>巡检目标</th>
                    <th>详情说明</th>
                    <th>状态</th>
                </tr>
            </thead>
            <tbody>`;
        logs.forEach(l => {
            html += `<tr>
                <td>${escapeHtml((l.timestamp || '').replace('T', ' ').substring(0, 19))}</td>
                <td><span class="tag tag-low">${escapeHtml(l.action)}</span></td>
                <td><code>${escapeHtml(l.operator)}</code></td>
                <td><code>${escapeHtml(l.target)}</code></td>
                <td>${escapeHtml(l.details)}</td>
                <td><span class="tag tag-${l.status === 'SUCCESS' ? 'low' : 'critical'}">${l.status === 'SUCCESS' ? '成功' : '失败'}</span></td>
            </tr>`;
        });
        html += `</tbody></table>`;
        box.innerHTML = html;
    } catch (e) {
        console.error(e);
    }
}

/* ---------------- 9. MSGBOX 开发者接口与专项测试工作台 ---------------- */
let currentMsgboxPresets = [];
let isMsgboxTokenMasked = true;
let currentMsgboxConfig = {
    target_url: "",
    default_token: "",
    masked_token: "",
    token_length: 0,
    configured: false
};

function getMsgBoxToolHTML() {
    return `
    <!-- 顶部状态栏与 Token 指纹卡片 -->
    <div class="card" style="margin-bottom: 20px; border-left: 4px solid #0284c7; background: linear-gradient(135deg, #ffffff 0%, #f0f9ff 100%);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px;">
            <div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 24px;">🧰</span>
                    <div>
                        <h3 style="font-size: 17px; font-weight: 700; color: #0369a1; margin: 0;">MsgBox 开发者接口与专项安全测试工作台</h3>
                        <p style="font-size: 13px; color: #64748b; margin: 3px 0 0 0;">针对已获授权目标的开发 API 接口调试、鉴权审计与非破坏性安全检查</p>
                    </div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="badge-pill" style="background: #e0f2fe; color: #0284c7; font-weight: 600;">⚡ API 联调模式</span>
                <button class="btn btn-primary" onclick="launchMsgBoxFullScan()" style="background: linear-gradient(135deg, #0284c7, #0369a1); font-weight: 600;">
                    🚀 启动带 Token 深度全量巡检
                </button>
            </div>
        </div>

        <div style="margin-top: 15px; padding: 12px 16px; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-size: 13px; font-weight: 700; color: #334155;">🔑 开发者 API 凭证 (Token):</span>
                <code id="msgbox-token-display" style="background: #f1f5f9; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #0f172a; word-break: break-all;">
                    未配置
                </code>
                <span class="tag tag-medium" style="font-size: 11px;">仅显示状态，不从服务端回传明文</span>
            </div>
            <div style="display: flex; gap: 6px;">
                <button class="btn btn-sm" onclick="toggleMsgBoxTokenVisibility()" style="border: 1px solid #cbd5e1; background: #fff; font-size: 12px;">
                    <span id="token-eye-icon">👁️</span> 显示/隐藏完整凭证
                </button>
                <button class="btn btn-sm" onclick="copyMsgBoxToken()" style="border: 1px solid #cbd5e1; background: #fff; font-size: 12px;">
                    📋 复制 Token
                </button>
            </div>
        </div>

        <div style="margin-top: 12px; display: grid; grid-template-columns: 1.3fr 1fr; gap: 10px;">
            <label style="font-size: 12px; color: #475569;">
                授权目标 URL
                <input id="msgbox-target-url" type="url" placeholder="https://your-authorized-lab.example" style="display: block; width: 100%; margin-top: 4px; padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box;">
            </label>
            <label style="font-size: 12px; color: #475569;">
                API Token（可选，留空则不注入鉴权头）
                <input id="msgbox-api-token" type="password" autocomplete="off" placeholder="由授权目标方提供" style="display: block; width: 100%; margin-top: 4px; padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box;">
            </label>
        </div>
    </div>

    <!-- 主界面左右两列布局 -->
    <div style="display: grid; grid-template-columns: 1fr 1.15fr; gap: 20px;">
        
        <!-- 左列：接口选择与请求构建器 -->
        <div class="card">
            <h4 style="font-size: 15px; font-weight: 700; color: #1e293b; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
                <span>🛠️</span> <span>请求构建器 (Request Composer)</span>
            </h4>

            <!-- 预置接口快速切换 -->
            <div style="margin-bottom: 15px;">
                <label style="font-size: 12px; font-weight: 600; color: #64748b; margin-bottom: 6px; display: block;">⚡ 预置接口快速载入:</label>
                <div id="msgbox-presets-box" style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                    <button class="btn btn-sm" onclick="loadMsgBoxPreset('get_messages')" style="text-align: left; padding: 8px 10px; border: 1px solid #e2e8f0; background: #f8fafc;">
                        <div style="font-weight: 600; font-size: 12px; color: #0284c7;">📥 消息拉取接口</div>
                        <div style="font-size: 11px; color: #64748b;">GET /api/messages</div>
                    </button>
                    <button class="btn btn-sm" onclick="loadMsgBoxPreset('send_message')" style="text-align: left; padding: 8px 10px; border: 1px solid #e2e8f0; background: #f8fafc;">
                        <div style="font-weight: 600; font-size: 12px; color: #16a34a;">📤 消息发布接口</div>
                        <div style="font-size: 11px; color: #64748b;">POST /api/send</div>
                    </button>
                    <button class="btn btn-sm" onclick="loadMsgBoxPreset('check_status')" style="text-align: left; padding: 8px 10px; border: 1px solid #e2e8f0; background: #f8fafc;">
                        <div style="font-weight: 600; font-size: 12px; color: #4f46e5;">🛡️ 状态与鉴权校验</div>
                        <div style="font-size: 11px; color: #64748b;">GET /api/status</div>
                    </button>
                    <button class="btn btn-sm" onclick="loadMsgBoxPreset('admin_probe')" style="text-align: left; padding: 8px 10px; border: 1px solid #e2e8f0; background: #f8fafc;">
                        <div style="font-weight: 600; font-size: 12px; color: #dc2626;">🔍 管理员越权探针</div>
                        <div style="font-size: 11px; color: #64748b;">GET /api/admin</div>
                    </button>
                </div>
            </div>

            <!-- 请求方法与路径 -->
            <div style="margin-bottom: 12px;">
                <label style="font-size: 12px; font-weight: 600; color: #64748b; margin-bottom: 4px; display: block;">请求目标 (Target Endpoint):</label>
                <div style="display: flex; gap: 8px;">
                    <select id="msgbox-method" style="width: 100px; padding: 8px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-weight: 700; font-family: monospace;">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                    </select>
                    <input type="text" id="msgbox-endpoint" value="/api/messages" placeholder="/api/messages" style="flex: 1; padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-family: monospace; font-size: 13px;">
                </div>
            </div>

            <!-- 请求头配置 -->
            <div style="margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <label style="font-size: 12px; font-weight: 600; color: #64748b;">HTTP 请求头 (Headers):</label>
                    <span style="font-size: 11px; color: #0284c7;">✓ 已自动注入 Authorization & X-API-Key</span>
                </div>
                <textarea id="msgbox-headers" rows="3" style="width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 6px; font-family: monospace; font-size: 12px; resize: vertical; box-sizing: border-box;" placeholder='{ "X-Custom-Header": "Value" }'></textarea>
            </div>

            <!-- 请求正文 JSON Body -->
            <div style="margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <label style="font-size: 12px; font-weight: 600; color: #64748b;">请求正文 (Request Body JSON):</label>
                    <span style="font-size: 11px; color: #94a3b8;">POST / PUT 时生效</span>
                </div>
                <textarea id="msgbox-body" rows="5" style="width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 6px; font-family: monospace; font-size: 12px; resize: vertical; box-sizing: border-box;" placeholder='{ "content": "Hello MsgBox" }'></textarea>
            </div>

            <!-- 执行操作按钮 -->
            <div style="display: flex; gap: 10px;">
                <button class="btn btn-primary" id="btn-msgbox-send" onclick="executeMsgBoxApiRequest()" style="flex: 1; padding: 10px; font-size: 13px; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 6px;">
                    <span>⚡ 发送 API 请求 (Live Send)</span>
                </button>
                <button class="btn" onclick="executeMsgBoxSecurityAudit()" style="border: 1px solid #0284c7; color: #0284c7; background: #f0f9ff; font-weight: 600; padding: 10px 14px;">
                    🛡️ 专项安全探针
                </button>
            </div>
        </div>

        <!-- 右列：实时响应与安全研判控制台 -->
        <div class="card" style="display: flex; flex-direction: column;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid #f1f5f9; padding-bottom: 8px;">
                <h4 style="font-size: 15px; font-weight: 700; color: #1e293b; margin: 0; display: flex; align-items: center; gap: 8px;">
                    <span>📡</span> <span>实时响应控制台 (Response & Telemetry)</span>
                </h4>
                <div id="msgbox-status-pill" style="display: none;">
                    <span class="tag tag-low" id="msgbox-status-code">-- 未请求 --</span>
                    <span style="font-size: 11px; color: #64748b; margin-left: 6px;" id="msgbox-time-cost">-- ms</span>
                </div>
            </div>

            <!-- 安全研判快讯 -->
            <div id="msgbox-security-insights" style="margin-bottom: 12px; padding: 10px 12px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; font-size: 12px; line-height: 1.6;">
                <span style="color: #64748b;">💡 点击左侧「⚡ 发送 API 请求」后，此处将呈现服务器响应结果、鉴权状态与安全指标研判。</span>
            </div>

            <!-- 响应内容选项卡 (JSON / Headers / Raw) -->
            <div style="display: flex; gap: 8px; margin-bottom: 8px; border-bottom: 1px solid #e2e8f0;">
                <button class="btn btn-sm" id="tab-btn-resp-body" onclick="switchMsgBoxResponseTab('body')" style="font-weight: 600; border-bottom: 2px solid #0284c7; background: transparent; border-radius: 0; color: #0284c7;">
                    📄 响应正文 (Body)
                </button>
                <button class="btn btn-sm" id="tab-btn-resp-headers" onclick="switchMsgBoxResponseTab('headers')" style="font-weight: 600; border-bottom: 2px solid transparent; background: transparent; border-radius: 0; color: #64748b;">
                    🏷️ 响应标头 (Headers)
                </button>
            </div>

            <!-- 响应正文视图 -->
            <div id="msgbox-resp-body-view" style="flex: 1; min-height: 260px; background: #0f172a; border-radius: 6px; padding: 12px; overflow: auto;">
                <pre id="msgbox-response-body" style="margin: 0; font-family: 'Fira Code', monospace; font-size: 12px; color: #38bdf8; white-space: pre-wrap; word-break: break-all;">// 等待发送请求...</pre>
            </div>

            <!-- 响应标头视图 (默认隐藏) -->
            <div id="msgbox-resp-headers-view" style="display: none; flex: 1; min-height: 260px; background: #f8fafc; border-radius: 6px; padding: 12px; border: 1px solid #e2e8f0; overflow: auto;">
                <pre id="msgbox-response-headers" style="margin: 0; font-family: monospace; font-size: 12px; color: #334155; white-space: pre-wrap;">// 暂无标头数据</pre>
            </div>
        </div>

    </div>

    <!-- 底部安全建议与防护卡片 -->
    <div class="card" style="margin-top: 20px; border-top: 3px solid #16a34a; background: #ffffff;">
        <h4 style="font-size: 14px; font-weight: 700; color: #166534; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
            <span>🛡️</span> <span>MsgBox 开发者 API 凭证安全规范与最佳实践</span>
        </h4>
        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; font-size: 12px; color: #475569; line-height: 1.6;">
            <div style="padding: 10px; background: #f0fdf4; border-radius: 6px; border: 1px solid #dcfce7;">
                <strong style="color: #15803d; display: block; margin-bottom: 4px;">1. 严禁前端公开暴露</strong>
                <span>该 API Token 具备开发者级别调用权限，禁止在客户端 Public JS 代码中明文硬编码，应通过服务端中继网关代理调用。</span>
            </div>
            <div style="padding: 10px; background: #f0fdf4; border-radius: 6px; border: 1px solid #dcfce7;">
                <strong style="color: #15803d; display: block; margin-bottom: 4px;">2. 开启速率限制 (Rate Limiting)</strong>
                <span>在 Vercel Edge Middleware 中为 <code>/api/*</code> 路由配置基于 IP 和 Token 的并发频次限制，防止自动化批量刷取。</span>
            </div>
            <div style="padding: 10px; background: #f0fdf4; border-radius: 6px; border: 1px solid #dcfce7;">
                <strong style="color: #15803d; display: block; margin-bottom: 4px;">3. 强化输入验证与转义</strong>
                <span>消息投递内容须在存储和渲染环节执行严格的 HTML 实体转义与长度截断，彻底阻断跨站脚本 (XSS) 注入风险。</span>
            </div>
        </div>
    </div>
    `;
}

async function initMsgBoxTool() {
    try {
        const res = await fetch(`${API_BASE}/msgbox/config`);
        if (res.ok) {
            const data = await res.json();
            currentMsgboxConfig = { ...currentMsgboxConfig, ...data };
            currentMsgboxPresets = data.presets || [];
            const targetInput = document.getElementById("msgbox-target-url");
            if (targetInput && data.target_url) targetInput.value = data.target_url;
            const tokenDisplay = document.getElementById("msgbox-token-display");
            if (tokenDisplay) tokenDisplay.innerText = data.masked_token || "未配置";
        }
    } catch (e) {
        console.error("Failed to load msgbox config:", e);
    }
}

function toggleMsgBoxTokenVisibility() {
    isMsgboxTokenMasked = !isMsgboxTokenMasked;
    const el = document.getElementById("msgbox-token-display");
    const icon = document.getElementById("token-eye-icon");
    const tokenInput = document.getElementById("msgbox-api-token");
    if (!el) return;
    const token = tokenInput?.value || "";
    if (!token) {
        el.innerText = currentMsgboxConfig.masked_token || (currentMsgboxConfig.configured ? "部署环境已配置" : "未配置");
        if (icon) icon.innerText = "👁️";
        return;
    }
    if (isMsgboxTokenMasked) {
        el.innerText = token.substring(0, 4) + "…" + token.substring(token.length - 4);
        if (icon) icon.innerText = "👁️";
    } else {
        el.innerText = token;
        if (icon) icon.innerText = "🙈";
    }
}

function copyMsgBoxToken() {
    const token = document.getElementById("msgbox-api-token")?.value || "";
    if (!token) {
        alert("当前未配置 API Token，请先在授权目标方提供后填写。");
        return;
    }
    navigator.clipboard.writeText(token).then(() => {
        alert("✅ API Token 已成功复制到剪贴板！");
    }).catch(() => {
        prompt("请手动复制 API Token:", token);
    });
}

function loadMsgBoxPreset(presetId) {
    const methodSelect = document.getElementById("msgbox-method");
    const endpointInput = document.getElementById("msgbox-endpoint");
    const bodyTextarea = document.getElementById("msgbox-body");
    
    if (presetId === "get_messages") {
        if (methodSelect) methodSelect.value = "GET";
        if (endpointInput) endpointInput.value = "/api/messages";
        if (bodyTextarea) bodyTextarea.value = "";
    } else if (presetId === "send_message") {
        if (methodSelect) methodSelect.value = "POST";
        if (endpointInput) endpointInput.value = "/api/send";
        if (bodyTextarea) bodyTextarea.value = JSON.stringify({
            "content": "这是一条通过 DAS-SentinelAgent 开发者工作台发送的测试消息",
            "sender": "DAS_Security_Tester",
            "timestamp": new Date().toISOString()
        }, null, 2);
    } else if (presetId === "check_status") {
        if (methodSelect) methodSelect.value = "GET";
        if (endpointInput) endpointInput.value = "/api/status";
        if (bodyTextarea) bodyTextarea.value = "";
    } else if (presetId === "admin_probe") {
        if (methodSelect) methodSelect.value = "GET";
        if (endpointInput) endpointInput.value = "/api/admin";
        if (bodyTextarea) bodyTextarea.value = "";
    }
}

async function executeMsgBoxApiRequest() {
    const method = document.getElementById("msgbox-method")?.value || "GET";
    const endpoint = document.getElementById("msgbox-endpoint")?.value || "/api/messages";
    const headersRaw = document.getElementById("msgbox-headers")?.value || "";
    const bodyRaw = document.getElementById("msgbox-body")?.value || "";
    
    const sendBtn = document.getElementById("btn-msgbox-send");
    const statusPill = document.getElementById("msgbox-status-pill");
    const statusCode = document.getElementById("msgbox-status-code");
    const timeCost = document.getElementById("msgbox-time-cost");
    const bodyView = document.getElementById("msgbox-response-body");
    const headersView = document.getElementById("msgbox-response-headers");
    const insightsBox = document.getElementById("msgbox-security-insights");
    const targetUrl = document.getElementById("msgbox-target-url")?.value.trim() || "";
    const apiToken = document.getElementById("msgbox-api-token")?.value || "";

    if (!targetUrl) {
        alert("请先填写已获授权的目标 URL；系统不会自动请求内置演示站点。");
        return;
    }

    let customHeaders = {};
    if (headersRaw.trim()) {
        try {
            customHeaders = JSON.parse(headersRaw);
        } catch (e) {
            alert("请求头 JSON 格式有误，请检查！");
            return;
        }
    }

    const requestPayload = {
        base_url: targetUrl,
        endpoint: endpoint,
        method: method,
        custom_headers: customHeaders,
        body_json: bodyRaw
    };
    // 为空时省略字段，让服务端按部署环境注入的 Token 处理；不在前端回显该凭证。
    if (apiToken) requestPayload.api_token = apiToken;

    if (sendBtn) {
        sendBtn.disabled = true;
        sendBtn.innerHTML = `<span>⏳ 请求发送中...</span>`;
    }

    try {
        const res = await fetch(`${API_BASE}/msgbox/execute`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(requestPayload)
        });

        const data = await res.json();
        
        if (statusPill) statusPill.style.display = "flex";
        if (statusCode) {
            statusCode.innerText = `${data.status_code || 0} ${data.status_code === 200 ? 'OK' : data.status_code === 403 ? 'Forbidden' : data.status_code === 401 ? 'Unauthorized' : 'Response'}`;
            statusCode.className = `tag tag-${data.status_code === 200 ? 'low' : data.status_code >= 400 ? 'critical' : 'medium'}`;
        }
        if (timeCost) timeCost.innerText = `⏱️ ${data.elapsed_ms || 0} ms`;

        if (bodyView) {
            if (data.response_json) {
                bodyView.innerText = JSON.stringify(data.response_json, null, 2);
                bodyView.style.color = "#38bdf8";
            } else {
                bodyView.innerText = data.response_body_raw || data.error || "// 无响应内容";
                bodyView.style.color = data.status_code === 200 ? "#4ade80" : "#fca5a5";
            }
        }

        if (headersView) {
            headersView.innerText = JSON.stringify(data.response_headers || {}, null, 2);
        }

        if (insightsBox && data.security_insights) {
            let insHtml = `<strong>🔍 安全研判与通信指标:</strong><ul style="margin: 4px 0 0 16px; padding: 0;">`;
            data.security_insights.forEach(item => {
                insHtml += `<li>${escapeHtml(item)}</li>`;
            });
            insHtml += `</ul>`;
            insightsBox.innerHTML = insHtml;
        }

    } catch (e) {
        console.error(e);
        if (bodyView) bodyView.innerText = `请求失败: ${e.message}`;
    } finally {
        if (sendBtn) {
            sendBtn.disabled = false;
            sendBtn.innerHTML = `<span>⚡ 发送 API 请求 (Live Send)</span>`;
        }
    }
}

function switchMsgBoxResponseTab(tabName) {
    const bodyView = document.getElementById("msgbox-resp-body-view");
    const headersView = document.getElementById("msgbox-resp-headers-view");
    const btnBody = document.getElementById("tab-btn-resp-body");
    const btnHeaders = document.getElementById("tab-btn-resp-headers");

    if (tabName === 'body') {
        if (bodyView) bodyView.style.display = "block";
        if (headersView) headersView.style.display = "none";
        if (btnBody) {
            btnBody.style.borderBottom = "2px solid #0284c7";
            btnBody.style.color = "#0284c7";
        }
        if (btnHeaders) {
            btnHeaders.style.borderBottom = "2px solid transparent";
            btnHeaders.style.color = "#64748b";
        }
    } else {
        if (bodyView) bodyView.style.display = "none";
        if (headersView) headersView.style.display = "block";
        if (btnHeaders) {
            btnHeaders.style.borderBottom = "2px solid #0284c7";
            btnHeaders.style.color = "#0284c7";
        }
        if (btnBody) {
            btnBody.style.borderBottom = "2px solid transparent";
            btnBody.style.color = "#64748b";
        }
    }
}

async function executeMsgBoxSecurityAudit() {
    const endpointInput = document.getElementById("msgbox-endpoint");
    if (endpointInput) endpointInput.value = "/api/admin";
    const methodSelect = document.getElementById("msgbox-method");
    if (methodSelect) methodSelect.value = "GET";
    await executeMsgBoxApiRequest();
}

async function launchMsgBoxFullScan() {
    const targetUrl = document.getElementById("msgbox-target-url")?.value.trim() || "";
    const apiToken = document.getElementById("msgbox-api-token")?.value || "";
    if (!targetUrl) {
        alert("请先填写已获授权的目标 URL；系统不会自动请求内置演示站点。");
        return;
    }
    if (!confirm("确定要针对已授权目标 " + targetUrl + " 启动全维度安全巡检任务吗？")) {
        return;
    }
    const scanPayload = {
        base_url: targetUrl,
        max_depth: 2,
        max_pages: 15
    };
    if (apiToken) scanPayload.api_token = apiToken;
    try {
        const res = await fetch(`${API_BASE}/msgbox/launch_scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(scanPayload)
        });
        const data = await res.json();
        if (data.status === "SUCCESS") {
            alert(`✅ 巡检任务启动成功！任务 ID: ${data.task_id}\n正在跳转至「巡检任务」列表查看实时进度...`);
            switchTab("tasks");
        } else {
            alert("启动任务失败: " + JSON.stringify(data));
        }
    } catch (e) {
        alert("请求异常: " + e.message);
    }
}
