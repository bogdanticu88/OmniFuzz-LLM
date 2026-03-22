import httpx
import json
from typing import Any, Dict, List
from .base import TargetAdapter

class RestApiAdapter(TargetAdapter):
    """
    Adapter for testing LLMs exposed over HTTP REST APIs.
    Supports session history for multi-turn attacks.
    """

    def __init__(self, endpoint_url: str, method: str = "POST", 
                 headers: Dict[str, str] = None, payload_template: Dict[str, Any] = None,
                 response_extractor: str = None):
        self.endpoint_url = endpoint_url
        self.method = method
        self.headers = headers or {"Content-Type": "application/json"}
        # Default payload template should support a 'messages' list for history.
        self.payload_template = payload_template or {"messages": "<MESSAGES>"}
        self.response_extractor = response_extractor or "response"
        
        self.history: List[Dict[str, str]] = []
        self.client = httpx.AsyncClient(timeout=30.0)

    def _inject_history(self, template: Any, prompt: str) -> Any:
        if isinstance(template, str):
            if template == "<PROMPT>":
                return prompt
            return template
        elif isinstance(template, dict):
            new_dict = {}
            for k, v in template.items():
                if k == "messages" and v == "<MESSAGES>":
                    new_dict[k] = self.history + [{"role": "user", "content": prompt}]
                elif isinstance(v, str) and "<PROMPT>" in v:
                    new_dict[k] = v.replace("<PROMPT>", prompt)
                else:
                    new_dict[k] = self._inject_history(v, prompt)
            return new_dict
        elif isinstance(template, list):
            return [self._inject_history(v, prompt) for v in template]
        return template

    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        payload = self._inject_history(self.payload_template, prompt)

        try:
            if self.method.upper() == "POST":
                response = await self.client.post(self.endpoint_url, headers=self.headers, json=payload)
            else:
                response = await self.client.request(self.method, self.endpoint_url, headers=self.headers, params=payload)
                
            response.raise_for_status()
            data = response.json()
            
            # Ollama API Chat extractor is deeper: data['message']['content']
            if "message" in data and "content" in data["message"]:
                resp_text = str(data["message"]["content"])
            else:
                # Fallback to key-based extractor
                resp_text = str(data.get(self.response_extractor, data))
            
            # Update internal history
            self.history.append({"role": "user", "content": prompt})
            self.history.append({"role": "assistant", "content": resp_text})
            
            return resp_text
            
        except httpx.HTTPError as exc:
            return f"[ERROR] Request failed: {exc}"

    async def reset_session(self):
        self.history = []
    
    async def close(self):
        await self.client.aclose()
