import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from backend.app.config import settings
from backend.app.database import init_db
from backend.app.baseline.scheduler_service import SchedulerService
from backend.app.api import tasks, findings, baselines, rules, agent, reports, msgbox_tool
from backend.app.api import heartbeat as heartbeat_api

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("das_sentinel.main")


async def _recover_pending_tasks(task_ids):
    """服务启动后顺序恢复遗留的待执行实例，避免重启瞬间并发洪峰。"""
    from backend.app.agent.orchestrator import InspectionOrchestrator

    for task_id in task_ids:
        try:
            await InspectionOrchestrator(task_id).run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Failed to recover pending task %s: %s", task_id, exc)


def _mark_running_tasks_interrupted(reason: str) -> list[str]:
    from backend.app.database import get_db_connection

    conn = get_db_connection()
    try:
        running_ids = [
            row["id"]
            for row in conn.execute("SELECT id FROM tasks WHERE status = 'RUNNING'").fetchall()
        ]
        conn.execute(
            """
            UPDATE tasks
            SET status = 'INTERRUPTED',
                current_stage = ?,
                finished_at = COALESCE(finished_at, datetime('now'))
            WHERE status = 'RUNNING'
            """,
            (reason,),
        )
        conn.commit()
        return running_ids
    finally:
        conn.close()


def _pending_task_ids() -> list[str]:
    from backend.app.database import get_db_connection

    conn = get_db_connection()
    try:
        return [
            row["id"]
            for row in conn.execute(
                "SELECT id FROM tasks WHERE status = 'PENDING' ORDER BY created_at ASC"
            ).fetchall()
        ]
    finally:
        conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时初始化数据库与定时调度器
    logger.info("Initializing DAS-SentinelAgent system database and background services...")
    init_db()
    recovery_task = None
    try:
        interrupted_ids = _mark_running_tasks_interrupted("服务重启导致本次执行中断，可重新发起巡检")
        pending_ids = _pending_task_ids()
        logger.info(
            "Startup reconciliation: interrupted=%d, pending_to_recover=%d",
            len(interrupted_ids),
            len(pending_ids),
        )
        if pending_ids:
            recovery_task = asyncio.create_task(
                _recover_pending_tasks(pending_ids),
                name="das-pending-task-recovery",
            )
    except Exception as e:
        logger.warning(f"Task reconciliation warning: {e}")

    SchedulerService.start()
    try:
        yield
    finally:
        # 关闭时清理，不把被取消的扫描伪装为完成。
        logger.info("Shutting down DAS-SentinelAgent background services...")
        if recovery_task and not recovery_task.done():
            recovery_task.cancel()
            await asyncio.gather(recovery_task, return_exceptions=True)
        _mark_running_tasks_interrupted("服务关停导致本次执行中断，可重新发起巡检")
        SchedulerService.shutdown()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="面向网站安全风险评估与敏感信息防泄露的智能巡检智能体原型系统 (安恒恒脑兼容)",
    lifespan=lifespan
)

# 跨域设置
cors_origins = [origin.strip() for origin in settings.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    )

# 挂载业务路由
app.include_router(tasks.router, prefix=settings.API_V1_STR)
app.include_router(findings.router, prefix=settings.API_V1_STR)
app.include_router(baselines.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(agent.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(msgbox_tool.router, prefix=settings.API_V1_STR)
app.include_router(heartbeat_api.router, prefix=settings.API_V1_STR)

# 挂载前端静态目录
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")), name="static")

@app.get("/")
async def index():
    from fastapi.responses import FileResponse
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {
        "status": "ONLINE",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs_url": "/docs",
        "hengnao_manifest": "/api/v1/agent/tools"
    }

@app.get("/health")
async def health_check():
    return {"status": "HEALTHY", "version": settings.APP_VERSION}
