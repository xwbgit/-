import asyncio
import multiprocessing
import threading
import time
import sys
import os

if sys.platform == "win32":
    try:
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn
from backend.app.config import settings

def run_target_lab():
    from target_lab.lab_server import lab_app
    print(f"[Target Lab] 正在启动政企模拟测试靶场: http://{settings.LAB_HOST}:{settings.LAB_PORT}")
    uvicorn.run(lab_app, host=settings.LAB_HOST, port=settings.LAB_PORT, log_level="warning")

def run_main_server():
    from backend.app.main import app
    print(f"[DAS-SentinelAgent] 正在启动智能巡检主系统与控制台: http://{settings.SERVER_HOST}:{settings.SERVER_PORT}")
    print(f"[API Docs] 交互式 Swagger 文档: http://{settings.SERVER_HOST}:{settings.SERVER_PORT}/docs")
    print(f"[HengNao Manifest] 恒脑平台工具定义: http://{settings.SERVER_HOST}:{settings.SERVER_PORT}/api/v1/agent/tools")
    uvicorn.run(app, host=settings.SERVER_HOST, port=settings.SERVER_PORT, log_level="info")

if __name__ == "__main__":
    print("=" * 70)
    print("DAS-SentinelAgent (安恒星巡 - 网站安全智能巡检系统)")
    print("=" * 70)
    
    # 生产/真实靶场模式默认不启动内置测试站点，避免把虚拟数据暴露到部署环境。
    # 需要本地回归时显式设置 ENABLE_BUILTIN_LAB=true。
    if settings.ENABLE_BUILTIN_LAB:
        lab_thread = threading.Thread(target=run_target_lab, daemon=True)
        lab_thread.start()
        time.sleep(1)
    else:
        print("[Target Lab] 未启动（如需本地回归，请设置 ENABLE_BUILTIN_LAB=true）")
    
    # 启动主服务
    run_main_server()
