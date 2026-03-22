import asyncio
import json
from typing import List, Dict, Any
from .adapters.base import TargetAdapter

class MultiTurnPlaybook:
    def __init__(self, name: str, steps: List[str]):
        self.name = name
        self.steps = steps

class MultiTurnFuzzer:
    """
    Simulates a multi-turn 'Boiling the Frog' attack.
    Maintains state across multiple prompts to gradually steer the LLM.
    """
    def __init__(self, adapter: TargetAdapter, evaluator: Any):
        self.adapter = adapter
        self.evaluator = evaluator
        self.history: List[Dict[str, str]] = []

    async def execute_playbook(self, playbook: MultiTurnPlaybook) -> bool:
        """
        Executes a sequence of prompts, checking for success at each step.
        """
        print(f"[*] Starting Multi-Turn Playbook: {playbook.name}")
        await self.adapter.reset_session()
        self.history = []

        for i, step_prompt in enumerate(playbook.steps):
            print(f"    [Turn {i+1}] Sending: {step_prompt[:50]}...")
            
            # In a real multi-turn, we'd include history. 
            # Our current RestApiAdapter is stateless, so we'll simulate history
            # by concatenating it or using a session-aware adapter.
            response = await self.adapter.send_prompt(step_prompt)
            
            # Evaluate after each step
            is_vuln, reason = await self.evaluator.evaluate(step_prompt, response)
            
            if is_vuln:
                print(f"    [!] VULNERABILITY TRIGGERED AT TURN {i+1}!")
                return True, response, reason
                
            # Add to history for next turn (if supported by the adapter)
            self.history.append({"role": "user", "content": step_prompt})
            self.history.append({"role": "assistant", "content": response})
            
            # Small delay to simulate human-like interaction
            await asyncio.sleep(0.5)

        print(f"    [-] Playbook '{playbook.name}' completed without triggering vulnerability.")
        return False, None, None
