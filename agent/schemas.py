"""
Strict Pydantic schemas for inter-agent messages.

Typed structured fields limit the attack surface vs. free-form text.
An oversized or out-of-range field is rejected at the gateway before
content ever reaches the recipient's LLM context.
"""

from pydantic import BaseModel, field_validator


class AgentMessage(BaseModel):
    """Structured output one agent sends to another via the gateway.

    All free-text is confined to the 'result' field which has a hard length
    cap. The other fields are typed and bounded, leaving no room for injection
    through schema fields.
    """
    from_agent: str   # sender's agent ID (must match the JWT's agent_id claim)
    to_agent:   str   # intended recipient — gateway enforces OPA trust check
    task_id:    str   # correlates this message to a specific work item
    result:     str   # the only free-text field — capped and sanitized
    confidence: float # 0.0 – 1.0; forces the sender to express uncertainty

    @field_validator("result")
    @classmethod
    def result_within_limit(cls, v: str) -> str:
        # 2000 chars is enough for any real task result.
        # Larger values are a red flag for injection padding or data exfiltration.
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
    """AgentMessage with an ECDSA-SHA256 signature over the payload fields.

    The gateway verifies sig + x5c before forwarding, giving the recipient
    proof that the message arrived intact and was created by a CA-issued identity.
    """
    sig: str  # base64url ECDSA-SHA256 over canonical JSON of the AgentMessage fields
    x5c: str  # base64-DER sender cert — gateway verifies it chains back to the trusted CA
