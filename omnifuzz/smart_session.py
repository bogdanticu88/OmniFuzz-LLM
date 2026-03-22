import asyncio
from typing import Any, List, Tuple
from .adapters.base import TargetAdapter

class SmartSessionFuzzer:
    """
    A 'Stealth' Fuzzer that rotates sessions immediately upon detection.
    If the LLM refuses or hits a guardrail, the current session is considered 
    'burned' and a new one is started with a different approach.
    """
    def __init__(self, adapter: TargetAdapter, evaluator: Any):
        self.adapter = adapter
        self.evaluator = evaluator
        self.burned_sessions = 0

    async def run_stealth_scan(self, payloads: List[str]):
        print(f"[*] Starting Stealth Scan. Session rotation enabled.")
        
        for i, payload in enumerate(payloads):
            print(f"[-] [Session {i+1-self.burned_sessions}] Sending: {payload[:40]}...")
            
            response = await self.adapter.send_prompt(payload)
            
            # Check for "Detection" (Model Refusal)
            is_refusal = any(r in response.lower() for r in [
                "i cannot", "i apologize", "as an ai", "i'm sorry", 
                "violate", "safety", "policy"
            ])
            
            if is_refusal:
                print(f"    [!] SESSION EXPOSED: Guardrail hit. Rotating session...")
                await self.adapter.reset_session()
                self.burned_sessions += 1
                # In a real attack, we'd wait or change IP/Proxy here.
                await asyncio.sleep(1) 
                continue

            # Evaluate for success
            is_vuln, reason = await self.evaluator.evaluate(payload, response)
            if is_vuln:
                print(f"    [!!!] VULNERABILITY FOUND: {reason}")
                return True, response
                
        print(f"[*] Scan complete. Total sessions burned: {self.burned_sessions}")
        return False, None
