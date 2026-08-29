# DAS-SentinelAgent 本地标注集检测评估报告

## 1. 评估边界

本报告只描述内置本地靶场 `http://127.0.0.1:8088` 在版本化标注集上的可复现结果，不代表互联网真实站点、未见组件或竞赛统一测试集上的效果。

本次评估使用：

- 标注集：`tests/fixtures/local_lab_ground_truth.json`
- 正样本：19 个（VULN 7、TAMPER 6、SENSITIVE 6）
- 负样本：4 个（错误校验位身份证、非 Luhn 卡号、占位手机号、无障碍隐藏内链）
- 外部工具：关闭，仅评估内置探针
- 执行日期：2026-08-28

## 2. 指标计算

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 × Precision × Recall / (Precision + Recall)
- False Positive Rate = FP / (FP + TN)

计算由 `backend/app/evaluation/metrics.py` 完成。正样本使用类别、URL 路径和标题正则与发现进行一对一匹配；未匹配发现计为 FP，未匹配正样本计为 FN，负样本无告警计为 TN。

## 3. 当前可复现结果

| 类别 | 正样本 | 负样本 | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| VULN | 7 | 0 | 7 | 0 | 0 | 0 | 1.000000 | 1.000000 | 1.000000 | N/A |
| TAMPER | 6 | 1 | 6 | 0 | 0 | 1 | 1.000000 | 1.000000 | 1.000000 | 0.000000 |
| SENSITIVE | 6 | 3 | 6 | 0 | 0 | 3 | 1.000000 | 1.000000 | 1.000000 | 0.000000 |
| 总计 | 19 | 4 | 19 | 0 | 0 | 4 | 1.000000 | 1.000000 | 1.000000 | 0.000000 |

上表仅对这 23 个已标注样本有效。样本量较小，不应简写为“系统通用准确率 100%”或“互联网场景零误报”。

## 4. 复现方法

PowerShell：

```powershell
$env:RUN_LAB_INTEGRATION="1"
python -m pytest -v tests/test_agent_orchestrator.py tests/test_deep_vulnerabilities.py
Remove-Item Env:RUN_LAB_INTEGRATION
```

`test_full_pipeline_against_lab` 会启动本地靶场、运行完整巡检链、读取标注集并断言 TP/FP/FN/TN。如需评估另一份已导出发现 JSON，可执行：

```powershell
python scripts/evaluate_detection.py findings.json tests/fixtures/local_lab_ground_truth.json --output metrics.json
```

## 5. 尚未覆盖

- 未进行大规模真实站点的统计显著性评估。
- 未将 Nuclei、Gitleaks 或 OWASP ZAP 的实际运行结果纳入本表。
- 未测量 CPU 占用、峰值内存、长时间稳定性或公网网络波动下的性能。
- 新增规则、靶场样本或匹配标准后，必须提升标注集版本并重新生成结果。
