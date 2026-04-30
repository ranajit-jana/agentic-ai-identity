"""
Strict Pydantic schemas for inter-agent messages.

Typed structured fields limit the attack surface vs. free-form text.
An oversized or out-of-range field is rejected at the gateway before
content ever reaches the recipient's LLM context.
"""

from pydantic import BaseModel, field_validator


class AgentMessage(BaseModel):
    """Structured output one agent sends to another via the gateway."""
    from_agent: str
    to_agent:   str
    task_id:    str
    result:     str
    confidence: float  # 0.0 – 1.0

    @field_validator("result")
    @classmethod
    def result_within_limit(cls, v: str) -> str:
        if len(v) > 2000:
            raise ValueError("result exceeds 2000 chars — possible injection padding")
        return v

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        return v


class SignedAgentMessage(AgentMessage):
    """AgentMessage with an ECDSA-SHA256 signature over the payload fields."""
    sig: str  # base64url ECDSA-SHA256 over canonical JSON of AgentMessage fields
    x5c: str  # base64-DER sender cert — gateway verifies it chains to the trusted CA
