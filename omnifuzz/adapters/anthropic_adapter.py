"""
Anthropic adapter — targets /v1/messages (Claude models).
Supports both plain chat and tool use (function calling).
"""
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from .base import TargetAdapter

logger = logging.getLogger("omnifuzz.adapters.anthropic")

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAdapter(TargetAdapter):
    """
    Adapter for the Anthropic Messages API (Claude models).

    Args:
        api_key:        Anthropic API key (sk-ant-...).
        model:          Model ID, e.g. "claude-3-5-sonnet-20241022".
        system_prompt:  Optional system prompt.
        max_tokens:     Max tokens in response (required by Anthropic API).
        temperature:    Sampling temperature.
        tools:          Optional list of tool definitions (Anthropic tool_use format).
                        If provided, the adapter will detect and log tool calls.
        endpoint_url:   Override the API URL (useful for proxies).
        timeout:        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-haiku-20240307",
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        endpoint_url: str = ANTHROPIC_API_URL,
        timeout: float = 60.0,
    ):
        self.model         = model
        self.system_prompt = system_prompt
        self.max_tokens    = max_tokens
        self.temperature   = temperature
        self.tools         = tools
        self.endpoint_url  = endpoint_url

        self.client = httpx.AsyncClient(
            headers={
                "x-api-key":         api_key,
                "anthropic-version": DEFAULT_ANTHROPIC_VERSION,
                "Content-Type":      "application/json",
            },
            timeout=timeout,
        )
        self.history: List[Dict[str, Any]] = []
        self.last_tool_calls: List[Dict[str, Any]] = []

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        self.last_tool_calls = []
        messages = list(self.history) + [{"role": "user", "content": prompt}]

        body: Dict[str, Any] = {
            "model":      self.model,
            "max_tokens": self.max_tokens,
            "messages":   messages,
        }
        if self.system_prompt:
            body["system"] = self.system_prompt
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if self.tools:
            body["tools"] = self.tools

        try:
            resp = await self.client.post(self.endpoint_url, json=body)
            resp.raise_for_status()
            data        = resp.json()
            stop_reason = data.get("stop_reason", "")
            content     = data.get("content", [])

            # Collect text and tool_use blocks
            text_parts: List[str] = []
            for block in content:
                if block.get("type") == "text":
                    text_parts.append(block["text"])
                elif block.get("type") == "tool_use":
                    self.last_tool_calls.append({
                        "id":    block.get("id"),
                        "name":  block.get("name"),
                        "input": block.get("input", {}),
                    })
                    logger.warning(
                        f"[TOOL_USE] Model called tool '{block.get('name')}' "
                        f"with input: {json.dumps(block.get('input', {}))[:200]}"
                    )
                    # Include tool call in text output for evaluator visibility
                    text_parts.append(
                        f"[TOOL_CALL: {block.get('name')}({json.dumps(block.get('input', {}))[:300]})]"
                    )

            response_text = "\n".join(text_parts) if text_parts else ""

            self.history.append({"role": "user",      "content": prompt})
            self.history.append({"role": "assistant", "content": response_text})

            if stop_reason == "max_tokens":
                logger.debug("Response truncated by max_tokens limit")

            return response_text

        except httpx.HTTPStatusError as e:
            logger.error(f"Anthropic API HTTP {e.response.status_code}: {e.response.text[:300]}")
            return f"[ERROR] HTTP {e.response.status_code}: {e.response.text[:200]}"
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected Anthropic response structure: {e}")
            return f"[ERROR] Unexpected response structure: {e}"
        except httpx.RequestError as e:
            logger.error(f"Request failed: {e}")
            return f"[ERROR] Request failed: {e}"

    async def reset_session(self) -> None:
        self.history = []
        self.last_tool_calls = []

    async def close(self) -> None:
        await self.client.aclose()
