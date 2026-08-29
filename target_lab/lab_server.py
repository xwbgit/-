import uvicorn
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

lab_app = FastAPI(title="政企模拟示范站点（安恒星巡巡检靶场）", description="包含政企网站典型安全漏洞、敏感信息泄露与挂马暗链的真实模拟测试集")

@lab_app.get("/", response_class=HTMLResponse)
async def home():
    # 模拟缺陷：缺失安全响应头、包含隐蔽暗链、CORS 允许任意 Origin
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>某市政务数据服务中心 - 官方门户</title>
    <style>
        body { font-family: "PingFang SC", "Microsoft YaHei", sans-serif; margin: 0; padding: 20px; background: #f8fafc; }
        .nav { background: #1e3a8a; color: #fff; padding: 15px 30px; border-radius: 8px; display: flex; gap: 20px; }
        .nav a { color: #fff; text-decoration: none; font-weight: bold; }
        .banner { margin-top: 20px; padding: 30px; background: #dbeafe; border-radius: 8px; }
        .news-list { margin-top: 20px; list-style: none; padding: 0; }
        .news-item { background: #fff; padding: 15px; border-radius: 6px; margin-bottom: 10px; border: 1px solid #e2e8f0; }
    </style>
</head>
<body>
    <div class="nav">
        <span>🏛️ 某市政务数据服务中心</span>
        <a href="/">首页</a>
        <a href="/news/notice_2026.html">政务公开与公示</a>
        <a href="/about.html">机构概况</a>
        <a href="/tampered_section.html">市民互动留言</a>
        <a href="/benign_validation.html">数据校验说明</a>
    </div>

    <div class="banner">
        <h2>推进数字化改革，构筑数字安全新防线</h2>
        <p>全面贯彻网络安全与数据安全法，严格落实敏感信息防护要求。</p>
    </div>

    <h3>最新通知公告</h3>
    <ul class="news-list">
        <li class="news-item"><a href="/news/notice_2026.html">【公示】2026年度数字民生扶持补贴资金发放名单汇总表</a></li>
        <li class="news-item"><a href="/about.html">【公告】政务云平台运维升级与网络安全巡检通知</a></li>
        <li class="news-item"><a href="/miner_test.html">【动态】关于数字化示范标杆园区建设方案的通知</a></li>
    </ul>

    <!-- 模拟安全缺陷：黑客注入的隐蔽暗链 (利用 CSS display:none 隐藏博彩链接) -->
    <div style="display:none;">
        <a href="https://www.macau-casino-bet888.com">澳门金沙真人在线博彩百家乐</a>
    </div>

    <!-- 模拟安全缺陷：利用绝对定位负坐标隐藏的黑产外链 -->
    <a href="https://www.pk10-lottery-cp88.vip" style="position:absolute; left:-9999px; top:-9999px;">2026特码六合彩直营平台</a>

    <footer style="margin-top: 50px; text-align: center; color: #64748b; font-size: 12px;">
        版权所有 © 2026 某市政务数据服务中心 浙ICP备20260826号
    </footer>
</body>
</html>
"""
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1d",
        "X-Powered-By": "PHP/7.4.3",
        "Access-Control-Allow-Origin": "https://evil-attacker.com",
        "Access-Control-Allow-Credentials": "true"
    }
    return HTMLResponse(content=html, headers=headers)

@lab_app.get("/news/notice_2026.html", response_class=HTMLResponse)
async def notice_page():
    # 模拟真实安全缺陷：运维发布公示表格未脱敏，直接泄露市民身份证、电话和银行卡号
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>2026年度数字民生扶持补贴资金发放名单公示</title>
    <style>
        body { font-family: sans-serif; padding: 20px; max-width: 900px; margin: 0 auto; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; font-size: 13px; }
        th { background: #f1f5f9; }
    </style>
</head>
<body>
    <h2>2026年度数字民生扶持补贴资金发放名单公示</h2>
    <p style="color: #64748b; font-size: 12px;">发布日期：2026-08-15 | 来源：数字化服务科</p>
    
    <p>为确保补贴发放公开透明，现将第一批符合申领条件的人员名单及收款账户公示如下：</p>
    
    <table>
        <thead>
            <tr>
                <th>姓名</th>
                <th>身份证号码 (真实校验)</th>
                <th>联系电话</th>
                <th>银行卡卡号</th>
                <th>补贴金额 (元)</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>张*伟</td>
                <td>110101199003072340</td>
                <td>13812345678</td>
                <td>6222021234567890128</td>
                <td>3,000.00</td>
            </tr>
            <tr>
                <td>李*明</td>
                <td>330102198506152011</td>
                <td>13987654321</td>
                <td>6217001234567890128</td>
                <td>4,500.00</td>
            </tr>
            <tr>
                <td>王*芳</td>
                <td>31010419921128302X</td>
                <td>15068862417</td>
                <td>6228481234567890128</td>
                <td>5,000.00</td>
            </tr>
        </tbody>
    </table>
</body>
</html>
"""
    return HTMLResponse(content=html)

@lab_app.get("/about.html", response_class=HTMLResponse)
async def about_page():
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>机构概况</title></head>
<body style="padding:20px; font-family:sans-serif;">
    <h2>机构概况与主要职责</h2>
    <p>负责统筹推进全市数字政府建设、数据要素市场培育以及公共数据资源开发利用与安全合规保障工作。</p>
    <p>联系邮箱：gov-admin@city-data.gov.cn</p>
</body>
</html>"""
    return HTMLResponse(content=html)


@lab_app.get("/benign_validation.html", response_class=HTMLResponse)
async def benign_validation_page():
    """负样本：格式相似但校验失败的证件、卡号和示例手机号。"""
    return HTMLResponse(content="""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>数据校验规则说明</title></head>
<body>
    <h2>表单校验说明</h2>
    <p>格式错误的证件号示例：110101199003072341</p>
    <p>未通过 Luhn 校验的卡号示例：6222021234567890123</p>
    <p>明确的占位手机号：13800000000</p>
    <a aria-hidden="true" style="display:none" href="/accessibility">无障碍辅助导航</a>
</body>
</html>""")

@lab_app.get("/tampered_section.html", response_class=HTMLResponse)
async def tampered_page():
    # 模拟页面被黑客篡改涂鸦
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>市民留言互动专栏</title></head>
<body style="padding:20px; background:#000; color:#00ff00; font-family:monospace;">
    <h1>Hacked by ShadowSec Team 2026</h1>
    <p>Your portal security is too weak! All administrative records have been seized.</p>
    <p>欢迎访问在线澳门金沙真人博彩百家乐，特码六合彩大曝光！</p>
</body>
</html>"""
    return HTMLResponse(content=html)

@lab_app.get("/miner_test.html", response_class=HTMLResponse)
async def miner_page():
    # 模拟被注入挖矿脚本与混淆 eval 代码
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>数字化示范标杆园区建设方案</title></head>
<body style="padding:20px;">
    <h2>数字化示范标杆园区建设方案</h2>
    <p>积极推动智能算力中心与绿色数据机房建设。</p>
    
    <!-- 模拟挂马载荷 -->
    <!-- application/json 不会作为 JavaScript 执行，仅保留检测特征。 -->
    <script type="application/json" id="malware-fixture">{"indicator":"coinhive.min.js","executable":false}</script>
</body>
</html>"""
    return HTMLResponse(content=html)

# 模拟配置文件与代码泄露缺陷
@lab_app.get("/.git/HEAD", response_class=PlainTextResponse)
async def git_leak():
    return PlainTextResponse("ref: refs/heads/main\n")

@lab_app.get("/.env", response_class=PlainTextResponse)
async def env_leak():
    return PlainTextResponse("""APP_NAME=GovDataPortal
APP_ENV=production
APP_KEY=base64:7vFwN4O2jXp9qZr8sL3mY0tW1kH6cE5a
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=gov_citizen_db
DB_USERNAME=root
DB_PASSWORD=GovAdminPassword2026!
ALIYUN_ACCESS_KEY_ID=LTAI4G7vXYZ123456789ABCD
ALIYUN_ACCESS_KEY_SECRET=abCDefGhIJKlmnoPQRSTUVW123456789
""")

@lab_app.get("/backup.sql", response_class=PlainTextResponse)
async def sql_leak():
    return PlainTextResponse("""-- 数据库导出备份
CREATE TABLE IF NOT EXISTS `sys_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
);
INSERT INTO `sys_users` VALUES (1, 'superadmin', '$2y$10$wKxN7z0p1Y...', 'admin@city-data.gov.cn');
""")

# ==========================================
# 🎯 真实工业级漏洞靶场交互端点 (供深度巡检引擎测试)
# ==========================================

@lab_app.get("/api/search", response_class=HTMLResponse)
async def api_search(q: str = ""):
    """XSS 漏洞靶场：未对用户输入进行 HTML 实体转义与上下文安全编码"""
    return HTMLResponse(content=f"""
    <html>
    <body>
        <h2>搜索结果</h2>
        <p>您搜索的关键词是: {q}</p>
        <input type="text" name="keyword" value="{q}">
    </body>
    </html>
    """)

@lab_app.get("/api/user", response_class=JSONResponse)
async def api_user(id: str = "1"):
    """SQL 注入漏洞靶场：包含错误回显、布尔差分与时间盲注"""
    import asyncio
    
    # 模拟时间盲注
    if "sleep" in id.lower() or "pg_sleep" in id.lower():
        await asyncio.sleep(2.0)
        return JSONResponse(content={"status": "success", "user": {"id": 1, "name": "admin_sleep_delay"}})
        
    # 模拟语法报错
    if "'" in id and not ("and" in id.lower() or "or" in id.lower()):
        return JSONResponse(
            status_code=500,
            content={"error": "SQL syntax error: You have an error in your SQL syntax near '\'' at line 1", "db": "MySQL 8.0.32"}
        )
        
    # 模拟布尔差分
    if "1=1" in id or "8374=8374" in id or "4821=4821" in id or id == "1":
        return JSONResponse(content={"status": "success", "data": {"id": 1, "username": "admin", "role": "superadministrator", "email": "admin@city-data.gov.cn"}})
    else:
        return JSONResponse(status_code=404, content={"status": "fail", "message": "User not found"})

@lab_app.get("/api/view", response_class=PlainTextResponse)
async def api_view(file: str = "notice.txt"):
    """LFI / 路径穿越漏洞靶场"""
    if "etc/passwd" in file.replace("\\", "/"):
        return PlainTextResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
    if "win.ini" in file.lower():
        return PlainTextResponse("[fonts]\n[extensions]\n[mci extensions]\n[files]\n")
    return PlainTextResponse(f"Reading file: {file} ... (File content: Normal Gov Notice Content)")

@lab_app.get("/api/render", response_class=HTMLResponse)
async def api_render(template: str = "World"):
    """SSTI 模板注入漏洞靶场 (支持动态素数乘积渲染)"""
    import re
    res_text = template
    # 支持动态模板数学表达式如 {{a*b}}, ${a*b}, #{a*b}
    math_match = re.search(r'[\{\$\#]\{(\d+)\*(\d+)\}', template)
    if math_match:
        val = str(int(math_match.group(1)) * int(math_match.group(2)))
        res_text = re.sub(r'[\{\$\#]\{\d+\*\d+\}', val, res_text)
    elif "{{47*23}}" in template or "${47*23}" in template or "#{47*23}" in template:
        res_text = template.replace("{{47*23}}", "1081").replace("${47*23}", "1081").replace("#{47*23}", "1081")
    elif "${49*7}" in template or "{{49*7}}" in template:
        res_text = template.replace("${49*7}", "343").replace("{{49*7}}", "343")
    return HTMLResponse(content=f"<div>Template Render Result: {res_text}</div>")

@lab_app.get("/api/ping", response_class=JSONResponse)
async def api_ping(host: str = "127.0.0.1"):
    """命令注入漏洞靶场 (支持动态算术 expr 计算回显)"""
    import asyncio
    import re
    if "sleep" in host.lower():
        await asyncio.sleep(2.0)
        return JSONResponse(content={"output": "PING executed with delay."})
    if "expr" in host.lower():
        m = re.search(r'expr\s+(\d+)\s*\+\s*(\d+)', host)
        if m:
            val = str(int(m.group(1)) + int(m.group(2)))
            return JSONResponse(content={"output": f"{val}\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms"})
    if "echo" in host.lower() or "das_cmd_exec" in host:
        return JSONResponse(content={"output": f"PING: das_cmd_exec_8394\n64 bytes from {host}: icmp_seq=1 ttl=64 time=0.045 ms"})
    return JSONResponse(content={"output": f"PING {host}: 64 bytes from {host}: icmp_seq=1 ttl=64 time=0.032 ms"})


@lab_app.get("/api/proxy", response_class=JSONResponse)
async def api_proxy(url: str = ""):
    """SSRF 服务端请求伪造靶场"""
    if "169.254.169.254" in url:
        return JSONResponse(content={"meta-data": {"ami-id": "ami-0123456789abcdef0", "instance-id": "i-0987654321fedcba0", "iam": {"role-name": "EC2GovRole"}}})
    if "127.0.0.1" in url or "localhost" in url or "2130706433" in url:
        return JSONResponse(content={"internal_service": "Redis Admin Cache", "port": 6379, "status": "CONNECTED"})
    return JSONResponse(content={"status": "proxy fetched"})

@lab_app.get("/api/profile", response_class=JSONResponse)
async def api_profile(user_id: int = 1):
    """BOLA / 越权漏洞靶场"""
    users_db = {
        1: {"id": 1, "username": "alice", "phone": "13800000001", "balance": "100.00"},
        2: {"id": 2, "username": "bob", "phone": "13800000002", "balance": "50000.00", "secret_memo": "内部机密备忘录"},
        99: {"id": 99, "username": "sysadmin", "token": "admin_jwt_secret_token_2026"}
    }
    data = users_db.get(user_id, {"error": "user not found"})
    return JSONResponse(content={"user_profile": data})

def start_lab_server():
    uvicorn.run(lab_app, host="127.0.0.1", port=8088, log_level="warning")

if __name__ == "__main__":
    start_lab_server()
