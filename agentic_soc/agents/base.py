"""Base class for tiered SOC agents with security guardrails and tool tracking."""

from __future__ import annotations
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import logging

from ..engine.guardrails import SecurityEvaluationGuard, ToolCallRecord, CanaryConfig

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(name)s] %(levelname)s: %(message)s")


class SOCAgent(ABC):
    """Abstract base class for autonomous SOC agents with guardrails and tool execution tracking."""

    def __init__(
        self,
        name: str,
        tier: int,
        role: str,
        guardrail: Optional[SecurityEvaluationGuard] = None
    ) -> None:
        self.name = name
        self.tier = tier
        self.role = role
        self.logger = logging.getLogger(self.name)
        self.guardrail = guardrail or SecurityEvaluationGuard()
        self.tool_calls_history: List[ToolCallRecord] = []
        
        # Injected system prompt with confidential canary
        canary_header = self.guardrail.get_system_prompt_canary_header()
        self.system_prompt = f"{canary_header}\nYou are {self.name}, Tier {self.tier} Agent ({self.role}) in the Agentic SOC."

    def record_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        result: Optional[str] = None,
        status: str = "success"
    ) -> ToolCallRecord:
        """Records tool invocation in transcript for LLM judge audit."""
        rec = ToolCallRecord(
            tool_name=tool_name,
            arguments=arguments,
            timestamp=datetime.now(timezone.utc).isoformat(),
            result=result,
            status=status
        )
        self.tool_calls_history.append(rec)
        return rec

    def get_transcript(self, user_input: str = "", agent_output: str = "") -> Dict[str, Any]:
        """Returns serialized transcript including tool calls and indicators."""
        return self.guardrail.serialize_judge_transcript(
            agent_name=self.name,
            system_prompt=self.system_prompt,
            user_input=user_input,
            agent_output=agent_output,
            tool_calls=self.tool_calls_history
        )

    @abstractmethod
    def process(self, *args: Any, **kwargs: Any) -> Any:
        """Core analytical execution turn."""
        pass
