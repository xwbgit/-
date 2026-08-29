import asyncio
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from plugins.core.base import ScanContext
from plugins.core.scope_manager import SRCScopingEngine


@dataclass
class CommandResult:
    command: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False


@dataclass
class ToolRunResult:
    tool: str
    status: str
    version: str = ""
    executable: str = ""
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None
    findings_count: int = 0
    reason: str = ""
    command: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ToolExecutionError(RuntimeError):
    pass


class AsyncCommandRunner:
    """不经过 shell 执行外部工具，并对运行时间和输出大小设限。"""

    def __init__(self, max_output_bytes: int = 5 * 1024 * 1024):
        self.max_output_bytes = max(1024, int(max_output_bytes))

    async def run(self, command: Sequence[str], timeout_seconds: float) -> CommandResult:
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *[str(part) for part in command],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=max(1.0, timeout_seconds))
        except asyncio.TimeoutError:
            timed_out = True
            process.kill()
            stdout, stderr = await process.communicate()
        duration = round(time.monotonic() - started, 3)
        stdout = stdout[: self.max_output_bytes].decode("utf-8", errors="replace")
        stderr = stderr[: self.max_output_bytes].decode("utf-8", errors="replace")
        return CommandResult(
            command=[str(part) for part in command],
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
        )


class BaseToolAdapter:
    tool_name = "external-tool"
    executable_names: Sequence[str] = ()
    version_args: Sequence[str] = ("--version",)
    accepted_exit_codes = {0}

    def __init__(self, runner: Optional[AsyncCommandRunner] = None):
        self.runner = runner or AsyncCommandRunner()

    def find_executable(self) -> Optional[str]:
        for name in self.executable_names:
            path = shutil.which(name)
            if path:
                return path
        return None

    async def get_version(self, executable: str) -> str:
        try:
            result = await self.runner.run([executable, *self.version_args], timeout_seconds=10)
        except (OSError, RuntimeError):
            return ""
        output = (result.stdout or result.stderr).strip().splitlines()
        return output[0][:200] if output else ""

    @staticmethod
    def assert_authorized(context: ScanContext) -> None:
        if not context.auth_domains:
            raise ToolExecutionError("未提供授权域名，禁止调用外部扫描工具")
        parsed = urlparse(context.target_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ToolExecutionError("外部工具仅支持有效的 HTTP/HTTPS 目标")
        if parsed.username or parsed.password:
            raise ToolExecutionError("目标 URL 不得携带明文认证信息")
        scope = SRCScopingEngine(auth_domains=context.auth_domains)
        if not scope.is_in_scope(context.target_url):
            raise ToolExecutionError("目标不在已授权域名范围内")

    @staticmethod
    def parse_json_lines(content: str) -> Iterable[Dict[str, Any]]:
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                yield value

    @staticmethod
    def read_text(path: Path, max_bytes: int = 5 * 1024 * 1024) -> str:
        if not path.exists() or not path.is_file():
            return ""
        with path.open("rb") as stream:
            return stream.read(max_bytes).decode("utf-8", errors="replace")

    async def run(self, context: ScanContext, timeout_seconds: float) -> tuple[ToolRunResult, List[Dict[str, Any]]]:
        raise NotImplementedError
