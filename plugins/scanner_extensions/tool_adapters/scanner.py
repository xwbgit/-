import logging
from typing import Dict, List, Type

from backend.app.config import settings
from plugins.core.base import BaseScanner, ScanContext

from .adapters import GitleaksAdapter, NucleiAdapter, ZapBaselineAdapter
from .base import AsyncCommandRunner, BaseToolAdapter, ToolRunResult


logger = logging.getLogger("das_sentinel.external_tools")


class OpenSourceToolScanner(BaseScanner):
    """
    将可选的第三方开源工具结果转换为统一 Finding。

    工具必须同时满足：管理员显式开启、位于允许清单、本机可执行文件
    存在，否则仅记录 SKIPPED，不伪造工具扫描结果。
    """

    ADAPTERS: Dict[str, Type[BaseToolAdapter]] = {
        "nuclei": NucleiAdapter,
        "gitleaks": GitleaksAdapter,
        "zap": ZapBaselineAdapter,
        "owasp-zap-baseline": ZapBaselineAdapter,
    }

    async def run(self, context: ScanContext) -> None:
        allowed = {
            item.strip().lower()
            for item in settings.EXTERNAL_TOOL_ALLOWLIST.split(",")
            if item.strip()
        }
        runner = AsyncCommandRunner(settings.EXTERNAL_TOOL_MAX_OUTPUT_BYTES)
        selected: List[BaseToolAdapter] = []
        if context.scan_scope.get("enable_vuln_check", True):
            for name in ("nuclei", "zap"):
                if name in allowed:
                    selected.append(self.ADAPTERS[name](runner))
        if context.scan_scope.get("enable_sensitive_check", True) and "gitleaks" in allowed:
            selected.append(GitleaksAdapter(runner))

        tool_runs: List[dict] = context.metadata.setdefault("tool_runs", [])
        if not selected:
            tool_runs.append(ToolRunResult(
                tool="open-source-tool-adapters",
                status="SKIPPED",
                reason="allowlist is empty or corresponding detection policies are disabled",
            ).to_dict())
            return

        for adapter in selected:
            try:
                run_result, findings = await adapter.run(
                    context,
                    timeout_seconds=settings.EXTERNAL_TOOL_TIMEOUT_SEC,
                )
            except Exception as exc:
                logger.exception("External tool adapter %s failed", adapter.tool_name)
                run_result = ToolRunResult(
                    tool=adapter.tool_name,
                    status="FAILED",
                    reason=str(exc)[:500],
                )
                findings = []
            context.add_findings(findings)
            tool_runs.append(run_result.to_dict())
