from abc import ABC, abstractmethod
from typing import Any, Dict

class TargetAdapter(ABC):
    """
    Abstract Base Class for connecting OmniFuzz to a target LLM application.
    By implementing this class, OmniFuzz can interact with REST APIs, WebSockets, CLI tools,
    or direct Python library integrations.
    """

    @abstractmethod
    async def send_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        Sends a prompt to the target application and returns the response text.

        Args:
            prompt (str): The adversarial payload to send.
            context (dict, optional): Additional context or session data.

        Returns:
            str: The response from the target.
        """
        pass

    @abstractmethod
    async def reset_session(self):
        """
        Resets the conversation or session state with the target.
        Crucial for multi-turn attacks or ensuring test isolation.
        """
        pass
