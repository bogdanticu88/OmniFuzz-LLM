"""
OpenAI-compatible adapter — targets /v1/chat/completions.
Covers: OpenAI, Azure OpenAI, LM Studio, vLLM, Groq, Together AI,
        and any OpenAI-format endpoint.
"""
import logging
from typing import Any, Dict, List, Optional
import httpx
from .base import TargetAdapter

logger = logging.getLogger("omnifuzz.adapters.openai")


class OpenAIAdapter(TargetAdapter):
    """
    Adapter for the OpenAI /v1/chat/completions API format.

    Args:
        endpoint_url:   Full URL, e.g. "https://api.openai.com/v1/chat/completions"
                        or "http://localhost:1234/v1/chat/completions" for LM Studio.
        api_key:        Bearer token (sk-...). Pass None for unauthenticated local endpoints.
        model:          Model identifier, e.g. "gpt-4o", "gpt-3.5-turbo".
        system_prompt:  Optional system message injected before every conversation.
        temperature:    Sampling temperature (default 0.7).
        max_tokens:     Max tokens in response (default 1024).
        extra_headers:  Additional HTTP headers (e.g. for Azure API-Version).
        timeout:        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        endpoint_url: str = "https://api.openai.com/v1/chat/completions",
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: float = 60.0,
    ):
        self.endpoint_url  = endpoint_url
        self.model         = model
        self.system_prompt = system_prompt
        self.temperature   = temperature
        self.max_tokens    = max_tokens

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if extra_headers:
            headers.update(extra_headers)

        self.client  = httpx.AsyncClient(headers=headers, timeout=timeout)
        self.history: List[Dict[str, str]] = []

    def _build_messages(self, prompt: str) -> List[Dict[str, str]]:
        messages = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.extend(self.history)
        messages.append({"role": "user", "content": prompt})
        return messages

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        messages = self._build_messages(prompt)
        body = {
            "model":       self.model,
            "messages":    messages,
            "temperature": self.temperature,
            "max_tokens":  self.max_tokens,
        }

        try:
            resp = await self.client.post(self.endpoint_url, json=body)
            resp.raise_for_status()
            data     = resp.json()
            text     = data["choices"][0]["message"]["content"]
            finish   = data["choices"][0].get("finish_reason", "")

            self.history.append({"role": "user",      "content": prompt})
            self.history.append({"role": "assistant", "content": text})

            if finish == "length":
                logger.debug("Response truncated by max_tokens limit")

            return text

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP {e.response.status_code}: {e.response.text[:200]}")
            return f"[ERROR] HTTP {e.response.status_code}: {e.response.text[:200]}"
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected response structure: {e}")
            return f"[ERROR] Unexpected response structure: {e}"
        except httpx.RequestError as e:
            logger.error(f"Request failed: {e}")
            return f"[ERROR] Request failed: {e}"

    async def reset_session(self) -> None:
        self.history = []

    async def close(self) -> None:
        await self.client.aclose()


class AzureOpenAIAdapter(OpenAIAdapter):
    """
    Convenience subclass for Azure OpenAI endpoints.

    Args:
        azure_endpoint:   e.g. "https://<resource>.openai.azure.com"
        deployment_name:  Your Azure deployment name.
        api_key:          Azure API key.
        api_version:      Azure API version string, e.g. "2024-02-01".
    """

    def __init__(
        self,
        azure_endpoint: str,
        deployment_name: str,
        api_key: str,
        api_version: str = "2024-02-01",
        **kwargs,
    ):
        url = (
            f"{azure_endpoint.rstrip('/')}/openai/deployments/"
            f"{deployment_name}/chat/completions?api-version={api_version}"
        )
        super().__init__(
            endpoint_url=url,
            api_key=None,  # Azure uses api-key header, not Bearer
            model=deployment_name,
            extra_headers={"api-key": api_key},
            **kwargs,
        )
