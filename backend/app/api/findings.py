import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.app.database import get_db_connection
from backend.app.models.finding import FindingResponse

router = APIRouter(prefix="/findings", tags=["风险发现与漏洞管理"])

# Keep status transitions explicit so malformed client input cannot create
# unrecognised states that the report, baseline and retest workflows cannot
# interpret.
VALID_FINDING_STATUSES = {"OPEN", "FIXED", "CONFIRMED", "IGNORED", "FALSE_POSITIVE"}

@router.get("", response_model=List[FindingResponse])
async def list_findings(
    task_id: Optional[str] = Query(None, description="按任务ID筛选"),
    category: Optional[str] = Query(None, description="按分类筛选 (VULN, SENSITIVE, TAMPER)"),
    severity: Optional[str] = Query(None, description="按严重等级筛选 (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[str] = Query(None, description="按状态筛选 (OPEN, FIXED, IGNORED)")
):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    
    if task_id:
        query += " AND task_id = ?"
        params.append(task_id)
    if category:
        query += " AND category = ?"
        params.append(category)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if status:
        query += " AND status = ?"
        params.append(status)
        
    query += " ORDER BY cvss_score DESC, created_at DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    findings = []
    for r in rows:
        evidence = json.loads(r["evidence"]) if r["evidence"] else {}
        findings.append(FindingResponse(
            id=r["id"],
            task_id=r["task_id"],
            category=r["category"],
            title=r["title"],
            severity=r["severity"],
            url=r["url"],
            param=r["param"],
            evidence=evidence,
            impact=r["impact"],
            remediation=r["remediation"],
            verified=r["verified"],
            cvss_score=r["cvss_score"],
            status=r["status"],
            src_type=r["src_type"] if "src_type" in r.keys() and r["src_type"] else "BASELINE_HYGIENE",
            created_at=r["created_at"],
            verified_at=r["verified_at"]
        ))

    return findings

@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    evidence = json.loads(row["evidence"]) if row["evidence"] else {}
    return FindingResponse(
        id=row["id"],
        task_id=row["task_id"],
        category=row["category"],
        title=row["title"],
        severity=row["severity"],
        url=row["url"],
        param=row["param"],
        evidence=evidence,
        impact=row["impact"],
        remediation=row["remediation"],
        verified=row["verified"],
        cvss_score=row["cvss_score"],
        status=row["status"],
        created_at=row["created_at"],
        verified_at=row["verified_at"]
    )

@router.post("/{finding_id}/status")
async def update_finding_status(finding_id: str, status: str = Query(..., description="新状态：CONFIRMED, OPEN, FIXED, IGNORED, FALSE_POSITIVE")):
    status = status.upper().strip()
    if status not in VALID_FINDING_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unsupported finding status: {status}")
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT title, url FROM findings WHERE id = ?", (finding_id,))
    f_row = cursor.fetchone()
    if not f_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Finding not found")
    
    now = datetime.now().isoformat()
    verified_val = 1 if status == "CONFIRMED" else 0
    
    cursor.execute("""
        UPDATE findings 
        SET status = ?, verified = ?, verified_at = ? 
        WHERE id = ?
    """, (status, verified_val, now, finding_id))
    
    # 记录审计日志
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, action, operator, target, details, status)
        VALUES (?, 'UPDATE_FINDING_STATUS', 'SECURITY_EXPERT', ?, ?, 'SUCCESS')
        """, (now, f_row["url"], f"专家人工审核漏洞 [{f_row['title']}] 状态更新为: {status}"))
        
    conn.commit()
    conn.close()
    return {"message": "Finding status updated", "finding_id": finding_id, "status": status, "verified": verified_val}

@router.delete("/{finding_id}")
async def delete_single_finding(finding_id: str):
    """彻底删除特定漏洞记录"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM findings WHERE id = ?", (finding_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Finding not found")
    cursor.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    conn.commit()
    conn.close()
    return {"message": "Finding deleted successfully", "finding_id": finding_id}

@router.post("/cleanup-false-positives")
async def cleanup_false_positives():
    """一键清空所有已标记为误报或已排除的漏洞记录"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM findings WHERE status = 'FALSE_POSITIVE' OR status = 'IGNORED'")
    rows = cursor.fetchall()
    deleted_count = len(rows)
    if deleted_count > 0:
        cursor.execute("DELETE FROM findings WHERE status = 'FALSE_POSITIVE' OR status = 'IGNORED'")
        conn.commit()
    conn.close()
    return {"deleted_count": deleted_count, "message": f"已彻底清空 {deleted_count} 项误报与已排除记录"}
@router.post("/batch-status")
async def batch_update_status(payload: dict):
    """批量更新指定漏洞的状态"""
    finding_ids = payload.get("finding_ids", [])
    status = str(payload.get("status", "CONFIRMED")).upper().strip()
    if status not in VALID_FINDING_STATUSES:
        raise HTTPException(status_code=422, detail=f"Unsupported finding status: {status}")
    if not finding_ids:
        return {"updated_count": 0, "message": "未提供漏洞 ID"}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.now().isoformat()
    verified_val = 1 if status == "CONFIRMED" else 0
    
    placeholders = ",".join(["?"] * len(finding_ids))
    params = [status, verified_val, now] + finding_ids
    
    cursor.execute(f"""
        UPDATE findings 
        SET status = ?, verified = ?, verified_at = ? 
        WHERE id IN ({placeholders})
    """, params)
    updated_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    return {"updated_count": updated_count, "message": f"已成功更新 {updated_count} 项记录状态"}

@router.post("/batch-delete")
async def batch_delete_findings(payload: dict):
    """批量彻底删除指定漏洞"""
    finding_ids = payload.get("finding_ids", [])
    if not finding_ids:
        return {"deleted_count": 0, "message": "未提供漏洞 ID"}
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholders = ",".join(["?"] * len(finding_ids))
    cursor.execute(f"DELETE FROM findings WHERE id IN ({placeholders})", finding_ids)
    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()
    return {"deleted_count": deleted_count, "message": f"已成功彻底删除 {deleted_count} 项漏洞记录"}

@router.post("/{finding_id}/retest")
async def retest_finding(finding_id: str):
    """一键非破坏性复测特定风险项，并自动更新修复状态与证据"""
    from backend.app.agent.verifier import FindingVerifier
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Finding not found")
        
    finding = dict(row)
    finding["evidence"] = json.loads(finding["evidence"]) if finding.get("evidence") else {}
    
    # 执行复测
    retest_result = await FindingVerifier.retest_single_finding(finding)
    new_status = retest_result["status_suggested"] if retest_result.get("retested") else finding.get("status", "OPEN")
    
    now = datetime.now().isoformat()
    cursor.execute("UPDATE findings SET status = ?, verified_at = ? WHERE id = ?", (new_status, now, finding_id))
    
    # 记录审计日志
    cursor.execute("""
    INSERT INTO audit_logs (timestamp, action, operator, target, details, status)
    VALUES (?, 'RETEST_FINDING', 'DAS_SENTINEL_AGENT', ?, ?, ?)
    """, (
        now,
        finding["url"],
        f"复测 [{finding['title']}] 结论: {retest_result['reason']}",
        "SUCCESS" if retest_result.get("retested") else "FAILED"
    ))
    
    conn.commit()
    conn.close()
    
    return {
        "finding_id": finding_id,
        "title": finding["title"],
        "url": finding["url"],
        "retest_result": retest_result,
        "current_status": new_status,
        "verified_at": now
    }

