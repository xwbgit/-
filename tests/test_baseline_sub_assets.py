import pytest
import json
from unittest.mock import patch, MagicMock
from backend.app.baseline.baseline_service import BaselineService
from backend.app.agent.orchestrator import InspectionOrchestrator

def test_compare_sub_assets_no_data():
    with patch('backend.app.baseline.baseline_service.get_db_connection') as mock_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.return_value = mock_conn
        
        # 模拟没有查询到数据
        mock_cursor.fetchone.side_effect = [None, None]
        
        result = BaselineService.compare_sub_assets("task_1", "task_2")
        assert "error" in result

def test_compare_sub_assets_diff():
    with patch('backend.app.baseline.baseline_service.get_db_connection') as mock_db:
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_db.return_value = mock_conn
        
        # 模拟基线数据
        base_sub_assets = [{"hostname": "a.example.com"}, {"hostname": "b.example.com"}]
        curr_sub_assets = [{"hostname": "b.example.com"}, {"hostname": "c.example.com"}]
        
        base_ports = [
            {"hostname": "a.example.com", "open_ports": [{"port": 80}]},
            {"hostname": "b.example.com", "open_ports": [{"port": 80, "service": "HTTP"}]}
        ]
        curr_ports = [
            {"hostname": "b.example.com", "open_ports": [{"port": 443, "service": "HTTPS"}]},
            {"hostname": "c.example.com", "open_ports": [{"port": 22}]}
        ]
        
        mock_cursor.fetchone.side_effect = [
            {
                "task_id": "task_1", 
                "target_url": "example.com", 
                "snapshot_time": "2024-01-01",
                "sub_assets_json": json.dumps(base_sub_assets),
                "port_results_json": json.dumps(base_ports)
            },
            {
                "task_id": "task_2", 
                "target_url": "example.com", 
                "snapshot_time": "2024-01-02",
                "sub_assets_json": json.dumps(curr_sub_assets),
                "port_results_json": json.dumps(curr_ports)
            }
        ]
        
        result = BaselineService.compare_sub_assets("task_1", "task_2")
        
        assert "error" not in result
        assert result["new_hosts_count"] == 1
        assert result["new_hosts"][0]["hostname"] == "c.example.com"
        assert result["removed_hosts_count"] == 1
        assert result["removed_hosts"][0]["hostname"] == "a.example.com"
        assert result["port_changes_count"] == 1
        assert result["port_changes"][0]["hostname"] == "b.example.com"
        assert 80 in result["port_changes"][0]["closed_ports"]
        assert 443 in result["port_changes"][0]["new_ports"]

def test_sub_asset_snapshots_api():
    from fastapi.testclient import TestClient
    from backend.app.main import app
    client = TestClient(app)
    
    with patch('backend.app.baseline.baseline_service.BaselineService.get_latest_sub_asset_snapshots', return_value=[{"id": "snap1"}]):
        resp = client.get("/api/v1/baselines/sub-assets/snapshots?target_url=http://example.com")
        assert resp.status_code == 200
        assert resp.json() == [{"id": "snap1"}]

def test_sub_asset_compare_api():
    from fastapi.testclient import TestClient
    from backend.app.main import app
    client = TestClient(app)
    
    with patch('backend.app.baseline.baseline_service.BaselineService.compare_sub_assets', return_value={"new_hosts_count": 0, "removed_hosts_count": 0, "port_changes_count": 0}):
        resp = client.get("/api/v1/baselines/sub-assets/compare?base_task_id=task1&current_task_id=task2")
        assert resp.status_code == 200
        assert resp.json()["new_hosts_count"] == 0

