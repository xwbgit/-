import json
import logging
from typing import Dict, Any, List, Optional
from backend.app.database import get_db_connection

logger = logging.getLogger("das_sentinel.baseline")

class BaselineService:
    """基线快照与安全异动 Diff 分析服务"""

    @classmethod
    def get_latest_snapshots(cls, target_url: str, limit: int = 10) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM baselines WHERE target_url = ? ORDER BY snapshot_time DESC LIMIT ?", (target_url, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @classmethod
    def compare_baselines(cls, base_task_id: str, current_task_id: str) -> Dict[str, Any]:
        """对比两次巡检任务的资产、页面 DOM 与风险项差异"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 加载两个任务的基线快照
        cursor.execute("SELECT * FROM baselines WHERE task_id = ?", (base_task_id,))
        base_row = cursor.fetchone()
        cursor.execute("SELECT * FROM baselines WHERE task_id = ?", (current_task_id,))
        curr_row = cursor.fetchone()
        
        # 加载两个任务的 findings
        cursor.execute("SELECT * FROM findings WHERE task_id = ?", (base_task_id,))
        base_findings = [dict(r) for r in cursor.fetchall()]
        cursor.execute("SELECT * FROM findings WHERE task_id = ?", (current_task_id,))
        curr_findings = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        if not base_row or not curr_row:
            return {"error": "未找到对应的基线快照数据"}
            
        base_doms = json.loads(base_row["dom_hashes_json"])
        curr_doms = json.loads(curr_row["dom_hashes_json"])
        
        base_pages = set(base_doms.keys())
        curr_pages = set(curr_doms.keys())
        
        new_pages = list(curr_pages - base_pages)
        removed_pages = list(base_pages - curr_pages)
        
        # 页面 DOM 异动比对 (潜在篡改或改版)
        tampered_pages = []
        for url in base_pages.intersection(curr_pages):
            if base_doms[url] != curr_doms[url]:
                tampered_pages.append({
                    "url": url,
                    "base_hash": base_doms[url][:16],
                    "curr_hash": curr_doms[url][:16],
                    "change": "DOM Content Modified"
                })
                
        # 漏洞比对 (基于 title + normalized url)
        def finding_fingerprint(f):
            return f"{f.get('category')}|{f.get('title')}|{f.get('url', '').split('?')[0]}"
            
        base_fp_map = {finding_fingerprint(f): f for f in base_findings}
        curr_fp_map = {finding_fingerprint(f): f for f in curr_findings}
        
        new_fps = set(curr_fp_map.keys()) - set(base_fp_map.keys())
        fixed_fps = set(base_fp_map.keys()) - set(curr_fp_map.keys())
        retained_fps = set(base_fp_map.keys()).intersection(set(curr_fp_map.keys()))
        
        new_findings = [curr_fp_map[k] for k in new_fps]
        fixed_findings = [base_fp_map[k] for k in fixed_fps]
        retained_findings = [curr_fp_map[k] for k in retained_fps]
        
        risk_trend = "STABLE"
        if len(new_findings) > len(fixed_findings):
            risk_trend = "INCREASED (风险上升)"
        elif len(fixed_findings) > len(new_findings):
            risk_trend = "DECREASED (风险收敛/好转)"
            
        return {
            "target_url": curr_row["target_url"],
            "base_task_id": base_task_id,
            "current_task_id": current_task_id,
            "base_time": base_row["snapshot_time"],
            "current_time": curr_row["snapshot_time"],
            "new_pages_count": len(new_pages),
            "new_pages": new_pages,
            "removed_pages_count": len(removed_pages),
            "removed_pages": removed_pages,
            "tampered_pages_count": len(tampered_pages),
            "tampered_pages": tampered_pages,
            "new_findings_count": len(new_findings),
            "new_findings": new_findings,
            "fixed_findings_count": len(fixed_findings),
            "fixed_findings": fixed_findings,
            "retained_findings_count": len(retained_findings),
            "retained_findings": retained_findings,
            "risk_trend": risk_trend
        }

    @classmethod
    def get_latest_sub_asset_snapshots(cls, target_url: str, limit: int = 10) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sub_asset_snapshots WHERE target_url = ? ORDER BY snapshot_time DESC LIMIT ?", (target_url, limit))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @classmethod
    def compare_sub_assets(cls, base_task_id: str, current_task_id: str) -> Dict[str, Any]:
        """对比两次巡检任务的子资产与端口异动差异"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM sub_asset_snapshots WHERE task_id = ?", (base_task_id,))
        base_row = cursor.fetchone()
        cursor.execute("SELECT * FROM sub_asset_snapshots WHERE task_id = ?", (current_task_id,))
        curr_row = cursor.fetchone()
        conn.close()
        
        if not base_row or not curr_row:
            return {"error": "未找到对应的子资产基线快照数据"}
            
        base_sub_assets = json.loads(base_row["sub_assets_json"])
        curr_sub_assets = json.loads(curr_row["sub_assets_json"])
        
        base_hosts = {asset["hostname"]: asset for asset in base_sub_assets if "hostname" in asset}
        curr_hosts = {asset["hostname"]: asset for asset in curr_sub_assets if "hostname" in asset}
        
        new_hosts = list(set(curr_hosts.keys()) - set(base_hosts.keys()))
        removed_hosts = list(set(base_hosts.keys()) - set(curr_hosts.keys()))
        
        # 端口异动比对
        base_ports = json.loads(base_row["port_results_json"]) if "port_results_json" in base_row else []
        curr_ports = json.loads(curr_row["port_results_json"]) if "port_results_json" in curr_row else []
        
        base_host_ports = {}
        for r in base_ports:
            base_host_ports[r["hostname"]] = {p["port"] for p in r.get("open_ports", [])}
            
        curr_host_ports = {}
        for r in curr_ports:
            curr_host_ports[r["hostname"]] = {p["port"] for p in r.get("open_ports", [])}
            
        port_changes = []
        for host in set(base_host_ports.keys()).intersection(set(curr_host_ports.keys())):
            b_ports = base_host_ports[host]
            c_ports = curr_host_ports[host]
            new_ports = list(c_ports - b_ports)
            closed_ports = list(b_ports - c_ports)
            if new_ports or closed_ports:
                port_changes.append({
                    "hostname": host,
                    "new_ports": new_ports,
                    "closed_ports": closed_ports
                })
                
        return {
            "target_url": curr_row["target_url"],
            "base_task_id": base_task_id,
            "current_task_id": current_task_id,
            "base_time": base_row["snapshot_time"],
            "current_time": curr_row["snapshot_time"],
            "new_hosts": [curr_hosts[h] for h in new_hosts],
            "new_hosts_count": len(new_hosts),
            "removed_hosts": [base_hosts[h] for h in removed_hosts],
            "removed_hosts_count": len(removed_hosts),
            "port_changes": port_changes,
            "port_changes_count": len(port_changes)
        }

