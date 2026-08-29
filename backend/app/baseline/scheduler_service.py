import logging
import uuid
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from typing import Dict, Any

from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.scheduler")

class SchedulerService:
    """定时与周期性巡检任务调度服务"""
    
    _scheduler: AsyncIOScheduler = None

    @classmethod
    def create_scan_run(cls, source_task_id: str, run_kind: str = "SCHEDULED_RUN") -> str:
        """从周期模板或历史任务复制配置，并为每次执行创建独立记录。"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id = ?", (source_task_id,))
        source = cursor.fetchone()
        if not source:
            conn.close()
            raise ValueError(f"Task {source_task_id} not found")

        source_dict = dict(source)
        parent_task_id = source_dict.get("parent_task_id") or source_task_id
        cursor.execute("SELECT COUNT(*) FROM tasks WHERE parent_task_id = ?", (parent_task_id,))
        run_number = cursor.fetchone()[0] + 1
        run_id = f"run-{uuid.uuid4().hex[:10]}"
        now = datetime.now().isoformat()
        label = "定时执行" if run_kind == "SCHEDULED_RUN" else "复测"
        cursor.execute("""
            INSERT INTO tasks (
                id, name, target_url, auth_domains, scan_scope, cron_expr,
                status, progress, current_stage, created_at, parent_task_id, run_kind
            ) VALUES (?, ?, ?, ?, ?, '', 'PENDING', 0, ?, ?, ?, ?)
        """, (
            run_id,
            f"{source_dict['name']} · {label} #{run_number}",
            source_dict["target_url"],
            source_dict["auth_domains"],
            source_dict["scan_scope"],
            f"{label}实例已创建，等待执行",
            now,
            parent_task_id,
            run_kind
        ))
        conn.commit()
        conn.close()
        return run_id

    @classmethod
    def start(cls):
        if not cls._scheduler or not cls._scheduler.running:
            cls._scheduler = AsyncIOScheduler()
            cls._scheduler.start()
            logger.info("AsyncIOScheduler started successfully.")
            cls._load_existing_scheduled_tasks()

    @classmethod
    def shutdown(cls):
        if cls._scheduler and cls._scheduler.running:
            cls._scheduler.shutdown()
            logger.info("AsyncIOScheduler stopped.")
        cls._scheduler = None

    @classmethod
    def _load_existing_scheduled_tasks(cls):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, cron_expr FROM tasks WHERE cron_expr != '' AND cron_expr IS NOT NULL")
        rows = cursor.fetchall()
        conn.close()
        for r in rows:
            cls.add_cron_job(r["id"], r["cron_expr"])

    @classmethod
    def add_cron_job(cls, task_id: str, cron_expr: str):
        if not cls._scheduler:
            cls.start()
        try:
            trigger = cls.validate_cron_expr(cron_expr)

            async def run_task_job():
                from backend.app.agent.orchestrator import InspectionOrchestrator
                logger.info(f"Triggering scheduled periodic inspection task {task_id}")
                run_id = cls.create_scan_run(task_id, run_kind="SCHEDULED_RUN")
                orchestrator = InspectionOrchestrator(run_id)
                await orchestrator.run()

            cls._scheduler.add_job(
                run_task_job,
                trigger=trigger,
                id=f"job_{task_id}",
                replace_existing=True
            )
            logger.info(f"Added periodic cron job for task {task_id} with expr: {cron_expr}")
        except Exception as e:
            logger.error(f"Failed to add cron job for task {task_id}: {e}")

    @staticmethod
    def validate_cron_expr(cron_expr: str) -> CronTrigger:
        """校验标准五段 Cron，并返回可直接注册的触发器。"""
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            raise ValueError("Cron 表达式必须包含 5 个字段：分 时 日 月 星期")
        minute, hour, day, month, day_of_week = parts
        try:
            return CronTrigger(
                minute=minute,
                hour=hour,
                day=day,
                month=month,
                day_of_week=day_of_week
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Cron 表达式无效: {exc}") from exc

    @classmethod
    def remove_cron_job(cls, task_id: str):
        if cls._scheduler:
            try:
                cls._scheduler.remove_job(f"job_{task_id}")
                logger.info(f"Removed cron job for task {task_id}")
            except Exception:
                pass

    @classmethod
    def get_job_info(cls, task_id: str) -> Dict[str, Any]:
        if not cls._scheduler:
            return {"scheduled": False}
        job = cls._scheduler.get_job(f"job_{task_id}")
        if job:
            next_run = job.next_run_time.isoformat() if job.next_run_time else None
            return {
                "scheduled": True,
                "job_id": job.id,
                "next_run_time": next_run
            }
        return {"scheduled": False}
