import json
import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from backend.app.database import get_db_connection
from backend.app.models.task import TaskCreateRequest, TaskResponse
from backend.app.agent.orchestrator import InspectionOrchestrator
from backend.app.baseline.scheduler_service import SchedulerService

router = APIRouter(prefix="/tasks", tags=["巡检任务管理"])

@router.post("", response_model=TaskResponse)
async def create_task(task_in: TaskCreateRequest, background_tasks: BackgroundTasks):
    if task_in.cron_expr:
        try:
            SchedulerService.validate_cron_expr(task_in.cron_expr)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    conn = get_db_connection()
    cursor = conn.cursor()
    
    task_id = f"task-{uuid.uuid4().hex[:8]}"
    now = datetime.now().isoformat()
    initial_status = "SCHEDULED" if task_in.cron_expr else "PENDING"
    initial_stage = "周期任务已登记，等待下次触发" if task_in.cron_expr else "任务已创建，等待调度"
    
    scan_scope = {
        "max_depth": task_in.max_depth,
        "max_pages": task_in.max_pages,
        "qps_limit": task_in.qps_limit,
        "enable_tamper_check": task_in.enable_tamper_check,
        "enable_sensitive_check": task_in.enable_sensitive_check,
        "enable_vuln_check": task_in.enable_vuln_check,
        "custom_sensitive_keywords": task_in.custom_sensitive_keywords
    }
    
    cursor.execute("""
    INSERT INTO tasks (id, name, target_url, auth_domains, scan_scope, cron_expr, status, progress, current_stage, created_at, run_kind)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 'MANUAL')
    """, (
        task_id, task_in.name, task_in.target_url,
        json.dumps(task_in.auth_domains), json.dumps(scan_scope),
        task_in.cron_expr, initial_status, initial_stage, now
    ))
    conn.commit()
    conn.close()
    
    # 若配置了 Cron 表达式，则注册到定时调度器
    if task_in.cron_expr:
        SchedulerService.add_cron_job(task_id, task_in.cron_expr)
    else:
        # 否则异步立即触发执行
        async def async_run():
            orchestrator = InspectionOrchestrator(task_id)
            await orchestrator.run()
        background_tasks.add_task(async_run)

    return TaskResponse(
        id=task_id,
        name=task_in.name,
        target_url=task_in.target_url,
        auth_domains=task_in.auth_domains,
        status=initial_status,
        progress=0,
        current_stage=initial_stage,
        created_at=now,
        started_at=None,
        finished_at=None,
        summary=None
    )

@router.get("", response_model=List[TaskResponse])
async def list_tasks():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    tasks = []
    for r in rows:
        summary = json.loads(r["summary"]) if r["summary"] else None
        auth_domains = json.loads(r["auth_domains"]) if r["auth_domains"] else []
        tasks.append(TaskResponse(
            id=r["id"],
            name=r["name"],
            target_url=r["target_url"],
            auth_domains=auth_domains,
            status=r["status"],
            progress=r["progress"],
            current_stage=r["current_stage"],
            created_at=r["created_at"],
            started_at=r["started_at"],
            finished_at=r["finished_at"],
            summary=summary
        ))
    return tasks

@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Task not found")
    summary = json.loads(row["summary"]) if row["summary"] else None
    auth_domains = json.loads(row["auth_domains"]) if row["auth_domains"] else []
    return TaskResponse(
        id=row["id"],
        name=row["name"],
        target_url=row["target_url"],
        auth_domains=auth_domains,
        status=row["status"],
        progress=row["progress"],
        current_stage=row["current_stage"],
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        summary=summary
    )

@router.post("/{task_id}/rerun")
async def rerun_task(task_id: str, background_tasks: BackgroundTasks):
    try:
        new_task_id = SchedulerService.create_scan_run(task_id, run_kind="RETEST")
    except ValueError:
        raise HTTPException(status_code=404, detail="Task not found")
    
    async def async_run():
        orchestrator = InspectionOrchestrator(new_task_id)
        await orchestrator.run()
    background_tasks.add_task(async_run)
    return {"message": "Task re-run triggered successfully", "task_id": new_task_id, "source_task_id": task_id}

@router.get("/{task_id}/details")
async def get_task_details(task_id: str):
    """获取任务的深度巡检详情数据 (包含 Burp Scanner 视图所需的 Issues、Sitemap、Raw Request/Response 与审计日志)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. 任务基础信息
    cursor.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
    task_row = cursor.fetchone()
    if not task_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Task not found")
    task = dict(task_row)
    task["summary"] = json.loads(task["summary"]) if task.get("summary") else {}
    task["auth_domains"] = json.loads(task["auth_domains"]) if task.get("auth_domains") else []
    task["scan_scope"] = json.loads(task["scan_scope"]) if task.get("scan_scope") else {}
    
    # 2. 该任务发现的所有漏洞与风险隐患 (Findings)
    cursor.execute("SELECT * FROM findings WHERE task_id = ? ORDER BY cvss_score DESC, created_at DESC", (task_id,))
    findings_rows = cursor.fetchall()
    findings = []
    for r in findings_rows:
        f = dict(r)
        evidence = json.loads(f.get("evidence") or "{}")
        f["evidence"] = evidence
        
        # 构造类似 Burp Suite 风格的标准 HTTP Request 与 Response 报文文本
        target_url = f.get("url", "")
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
            
        req_headers = evidence.get("request_headers") or {}
        request_method = evidence.get("request_method", "GET")
        req_headers_str = f"[根据发现记录重建，非原始报文]\r\n{request_method} {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\n"
        for k, v in req_headers.items():
            req_headers_str += f"{k}: {v}\r\n"
        f["raw_request"] = req_headers_str
        
        resp_headers = evidence.get("response_headers") or {}
        resp_status = evidence.get("response_status")
        if resp_status is None:
            f["raw_response"] = "[未保存原始响应，无法重建 HTTP 状态与响应头]"
        else:
            resp_headers_str = f"HTTP/1.1 {resp_status}\r\n"
            for k, v in resp_headers.items():
                resp_headers_str += f"{k}: {v}\r\n"
            matched_sample = evidence.get("matched_snippet", "")
            f["raw_response"] = f"{resp_headers_str}\r\n{matched_sample}"
        findings.append(f)
        
    # 3. 站点资产拓扑地图 (Sitemap)
    cursor.execute("SELECT * FROM baselines WHERE task_id = ?", (task_id,))
    base_row = cursor.fetchone()
    sitemap = []
    if base_row:
        try:
            sitemap = json.loads(base_row["assets_json"])
        except Exception:
            sitemap = []
            
    # 4. 针对该目标的审计操作流水与 HTTP 探测流水 (Audit Logs & Probes History)
    cursor.execute("SELECT * FROM audit_logs WHERE target = ? OR details LIKE ? ORDER BY timestamp DESC LIMIT 50",
                   (task["target_url"], f"%{task_id}%"))
    logs = [dict(r) for r in cursor.fetchall()]
    
    # 5. 技术栈架构与拓扑指纹分析 (若任务中未持久化，则即时推断)
    from plugins.scanner_extensions.sub_assets.fingerprint_detector import ArchitectureFingerprintDetector
    architecture = task.get("summary", {}).get("architecture")
    if not architecture:
        architecture = ArchitectureFingerprintDetector.detect_architecture(task["target_url"], sitemap, findings)
    
    conn.close()
    
    return {
        "task": task,
        "findings_count": len(findings),
        "findings": findings,
        "sitemap_count": len(sitemap),
        "sitemap": sitemap,
        "audit_logs": logs,
        "architecture": architecture
    }

@router.delete("/{task_id}")
async def delete_task(task_id: str):
    """彻底删除指定任务及其相关数据"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, cron_expr FROM tasks WHERE id = ?", (task_id,))
    task = cursor.fetchone()
    if not task:
        conn.close()
        raise HTTPException(status_code=404, detail="Task not found")
        
    cursor.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    cursor.execute("DELETE FROM findings WHERE task_id = ?", (task_id,))
    cursor.execute("DELETE FROM baselines WHERE task_id = ?", (task_id,))
    conn.commit()
    conn.close()
    if task["cron_expr"]:
        SchedulerService.remove_cron_job(task_id)
    return {"message": "Task and related records deleted successfully", "task_id": task_id}


@router.post("/cleanup/keep-latest")
async def cleanup_keep_latest_tasks():
    """一键精简冗余历史任务：每个目标网站仅保留最新 1 次巡检记录，删除旧任务"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 查找每个 target_url 最新的 task id
    cursor.execute("""
        SELECT id FROM tasks 
        WHERE id IN (
            SELECT id FROM (
                SELECT id, target_url, ROW_NUMBER() OVER (PARTITION BY target_url ORDER BY created_at DESC) as rn
                FROM tasks
            ) WHERE rn = 1
        )
    """)
    latest_ids = [r["id"] for r in cursor.fetchall()]
    
    if not latest_ids:
        conn.close()
        return {"deleted_count": 0, "message": "暂无需要清理的历史任务"}
    
    placeholders = ",".join(["?"] * len(latest_ids))
    cursor.execute(f"SELECT id FROM tasks WHERE id NOT IN ({placeholders})", latest_ids)
    to_delete = [r["id"] for r in cursor.fetchall()]
    
    if to_delete:
        del_placeholders = ",".join(["?"] * len(to_delete))
        cursor.execute(f"DELETE FROM tasks WHERE id IN ({del_placeholders})", to_delete)
        cursor.execute(f"DELETE FROM findings WHERE task_id IN ({del_placeholders})", to_delete)
        cursor.execute(f"DELETE FROM baselines WHERE task_id IN ({del_placeholders})", to_delete)
        conn.commit()
    
    conn.close()
    for task_id in to_delete:
        SchedulerService.remove_cron_job(task_id)
    return {"deleted_count": len(to_delete), "message": f"成功清理 {len(to_delete)} 个冗余历史任务，每个目标仅保留最新巡检基线。"}

@router.post("/cleanup/all-completed")
async def cleanup_all_completed_tasks():
    """清空所有历史已完成任务与关联记录"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM tasks WHERE status = 'COMPLETED'")
    completed_ids = [r["id"] for r in cursor.fetchall()]
    if completed_ids:
        del_placeholders = ",".join(["?"] * len(completed_ids))
        cursor.execute(f"DELETE FROM tasks WHERE id IN ({del_placeholders})", completed_ids)
        cursor.execute(f"DELETE FROM findings WHERE task_id IN ({del_placeholders})", completed_ids)
        cursor.execute(f"DELETE FROM baselines WHERE task_id IN ({del_placeholders})", completed_ids)
        conn.commit()
    conn.close()
    return {"deleted_count": len(completed_ids), "message": f"已清空 {len(completed_ids)} 条历史已完成巡检任务。"}

@router.post("/batch-delete")
async def batch_delete_tasks(payload: dict):
    """批量删除指定 ID 的任务"""
    task_ids = payload.get("task_ids", [])
    if not task_ids:
        return {"deleted_count": 0, "message": "未提供待删除的任务 ID"}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholders = ",".join(["?"] * len(task_ids))
    cursor.execute(f"DELETE FROM tasks WHERE id IN ({placeholders})", task_ids)
    cursor.execute(f"DELETE FROM findings WHERE task_id IN ({placeholders})", task_ids)
    cursor.execute(f"DELETE FROM baselines WHERE task_id IN ({placeholders})", task_ids)
    conn.commit()
    conn.close()
    for task_id in task_ids:
        SchedulerService.remove_cron_job(task_id)
    return {"deleted_count": len(task_ids), "message": f"已成功删除 {len(task_ids)} 个任务"}

