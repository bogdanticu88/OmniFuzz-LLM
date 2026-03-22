"""
Subprocess adapter — runs a local model via CLI (llama.cpp, ollama CLI, etc.)
and communicates through its stdin/stdout.
"""
import asyncio
import logging
import shlex
from typing import Any, Dict, Optional
from .base import TargetAdapter

logger = logging.getLogger("omnifuzz.adapters.subprocess")


class SubprocessAdapter(TargetAdapter):
    """
    Adapter for local models invoked as a subprocess.

    The adapter spawns the process once, then writes prompts to stdin and
    reads responses from stdout, making it suitable for interactive CLI
    models (llama.cpp interactive mode, custom scripts, etc.).

    For non-interactive CLIs (one-shot execution), set ``one_shot=True`` and
    the adapter will spawn a fresh process for every prompt.

    Args:
        command:         Shell command to launch the model, e.g.
                         "llama-cli -m model.gguf --interactive-first"
        prompt_prefix:   Text prepended to every user prompt (e.g. "User: ").
        prompt_suffix:   Text appended after every user prompt (e.g. "\\nAssistant:").
        stop_token:      String that signals end of model response in stdout.
        one_shot:        If True, spawn a new process per prompt (safer but slower).
        response_timeout: Seconds to wait for a response before timing out.
        encoding:        Process stdio encoding.
    """

    def __init__(
        self,
        command: str,
        prompt_prefix: str = "User: ",
        prompt_suffix: str = "\nAssistant:",
        stop_token: str = "User:",
        one_shot: bool = True,
        response_timeout: float = 60.0,
        encoding: str = "utf-8",
    ):
        self.command          = command
        self.prompt_prefix    = prompt_prefix
        self.prompt_suffix    = prompt_suffix
        self.stop_token       = stop_token
        self.one_shot         = one_shot
        self.response_timeout = response_timeout
        self.encoding         = encoding

        self._process: Optional[asyncio.subprocess.Process] = None

    async def _spawn(self) -> asyncio.subprocess.Process:
        args = shlex.split(self.command)
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.debug(f"Spawned subprocess PID {process.pid}: {self.command}")
        return process

    async def _read_until_stop(
        self, stdout: asyncio.StreamReader, stop: str
    ) -> str:
        """Read stdout lines until we see the stop_token or EOF."""
        lines = []
        try:
            async with asyncio.timeout(self.response_timeout):
                while True:
                    line = await stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(self.encoding, errors="replace")
                    if stop and stop in decoded:
                        break
                    lines.append(decoded)
        except TimeoutError:
            logger.warning(f"Subprocess response timed out after {self.response_timeout}s")
        return "".join(lines).strip()

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        full_input = f"{self.prompt_prefix}{prompt}{self.prompt_suffix}\n"
        encoded    = full_input.encode(self.encoding)

        if self.one_shot:
            # Spawn, write, read, terminate
            process = await self._spawn()
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(input=encoded),
                    timeout=self.response_timeout,
                )
                response = stdout_data.decode(self.encoding, errors="replace").strip()
                if not response and stderr_data:
                    logger.debug(f"stderr: {stderr_data.decode(self.encoding, errors='replace')[:200]}")
                return response
            except TimeoutError:
                process.kill()
                logger.warning("Subprocess one-shot timed out")
                return "[ERROR] Subprocess timed out"
            except Exception as e:
                logger.error(f"Subprocess error: {e}")
                return f"[ERROR] Subprocess error: {e}"
        else:
            # Persistent process
            if self._process is None or self._process.returncode is not None:
                self._process = await self._spawn()

            try:
                self._process.stdin.write(encoded)
                await self._process.stdin.drain()
                return await self._read_until_stop(self._process.stdout, self.stop_token)
            except Exception as e:
                logger.error(f"Persistent subprocess error: {e}")
                self._process = None
                return f"[ERROR] Subprocess error: {e}"

    async def reset_session(self) -> None:
        """Kill and restart the persistent process (if running)."""
        if self._process and self._process.returncode is None:
            self._process.kill()
            await self._process.wait()
        self._process = None

    async def close(self) -> None:
        await self.reset_session()
