"""
Langfuse observability client — mode-aware tracing for the agent and gateway.

Two modes driven by TRACING_MODE env var:

  debug:      Full span tree per request (gateway auth, OPA decision, tool forward,
              sanitizer). Every LangGraph node is traced via callback handler.
              No LLM judge — OPA already names the denial reason precisely.

  production: LLM prompt + response only (via LangGraph callback handler).
              LLM judge evaluates task prompts and sanitized tool responses
              asynchronously before they reach the LLM context.

If LANGFUSE_PUBLIC_KEY / LANGFUSE_SECRET_KEY are absent, every function returns
a no-op stub — the rest of the codebase never needs to guard against None.

Langfuse v4 env vars (auto-read by the SDK — no constructor args needed):
  LANGFUSE_PUBLIC_KEY
  LANGFUSE_SECRET_KEY
  LANGFUSE_BASE_URL     (default: https://cloud.langfuse.com)
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Mode controls which observability features are active (see module docstring)
TRACING_MODE: str = os.getenv("TRACING_MODE", "production")

_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY", "")
_SECRET_KEY = os.getenv("LANGFUSE_SECRET_KEY", "")

# Lazy-initialised singleton — avoids import-time errors when keys are absent
_client = None


# ---------------------------------------------------------------------------
# No-op stubs — returned when Langfuse is not configured
# ---------------------------------------------------------------------------

class _NoOpTrace:
    """Returned by start_trace() when Langfuse credentials are absent."""
    id = ""   # real traces have a UUID here; code that reads .id gets an empty string


class _NoOpSpan:
    """Returned by start_span() when Langfuse credentials are absent."""

    def update(self, **kw):
        pass

    def end(self, **kw):
        pass


# ---------------------------------------------------------------------------
# Client initialisation
# ---------------------------------------------------------------------------

def _get_client():
    """Return the Langfuse singleton, or None if the package / credentials are absent."""
    global _client
    if _client is not None:
        return _client
    if not _PUBLIC_KEY or not _SECRET_KEY:
        return None
    # Placeholders in .env are not real keys
    if _PUBLIC_KEY.startswith("pk-lf-...") or _SECRET_KEY.startswith("sk-lf-..."):
        return None
    try:
        from langfuse import Langfuse
        # Langfuse v4 auto-reads LANGFUSE_PUBLIC_KEY, LANGFUSE_SECRET_KEY,
        # and LANGFUSE_BASE_URL from the environment
        _client = Langfuse()
        return _client
    except ImportError:
        # langfuse package not installed — running without observability
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_mode() -> str:
    """Return the active tracing mode: 'debug' or 'production'."""
    return TRACING_MODE


def get_callback_handler(trace_id: str = ""):
    """
    LangGraph / LangChain callback handler — auto-traces every graph node.

    Requires: pip install langchain  (the base package, separate from langchain-core)
    Returns None when langchain is not installed or Langfuse is not configured.
    Callers must check for None before registering.

    debug mode:      attaches to the existing trace so LLM spans nest under it
    production mode: creates its own trace (only LLM calls are recorded)
    """
    lf = _get_client()
    if lf is None:
        return None
    try:
        # langfuse.langchain requires the base `langchain` package
        from langfuse.langchain import CallbackHandler
        kwargs: dict = {}
        if trace_id:
            # Link LangGraph spans to the existing trace so they nest correctly
            kwargs["trace_id"] = trace_id
        return CallbackHandler(**kwargs)
    except (ImportError, ModuleNotFoundError):
        # langchain base package not installed — skip callback tracing
        return None


def start_trace(name: str, input: str = "", metadata: dict | None = None):
    """
    Reserve a new Langfuse trace ID for a single agent task.

    Returns a lightweight wrapper with .id (UUID string).
    Returns a no-op stub when Langfuse is not configured.

    Uses create_trace_id() so the trace ID is known before any spans are created —
    this lets us pass it in headers to the gateway for cross-process span linking.
    """
    lf = _get_client()
    if lf is None:
        return _NoOpTrace()

    # Reserve the trace ID — spans created with this ID will group under one trace
    trace_id = lf.create_trace_id()

    # Create a root span to record task input/output and make the trace visible in the UI
    lf.start_observation(
        trace_context={"trace_id": trace_id},
        name=name,
        as_type="span",
        input=input,
        metadata=metadata or {},
    )

    # Return a lightweight handle so callers can read the ID without holding the span
    class _TraceHandle:
        id = trace_id

    return _TraceHandle()


def start_span(trace_id: str, name: str, input: dict | None = None):
    """
    Create a child span on an existing trace identified by trace_id.

    Used by the gateway to add per-step spans to the agent's trace.
    Spans are created with start_observation() pointing at the parent trace_id.
    Returns a no-op stub when Langfuse is not configured or trace_id is empty.
    """
    lf = _get_client()
    if lf is None or not trace_id:
        return _NoOpSpan()
    try:
        return lf.start_observation(
            trace_context={"trace_id": trace_id},
            name=name,
            as_type="span",
            input=input or {},
        )
    except Exception:
        return _NoOpSpan()


def end_span(span, output=None, level: str = "DEFAULT") -> None:
    """
    Close a span with output and log level.
    level='WARNING' makes the span visually highlighted in the Langfuse UI —
    used for OPA denials so they stand out in the trace timeline.
    """
    if isinstance(span, _NoOpSpan):
        return
    try:
        # Update sets the output + level, then end() sends the event
        span.update(output=output, level=level)
        span.end()
    except Exception:
        pass  # span errors must never break the request path


def post_score(trace_id: str, name: str, value: float, comment: str = "") -> None:
    """
    Post a judge verdict as a numeric score on an existing trace.
    Scores appear in the Langfuse UI as a time-series metric per trace.
    """
    lf = _get_client()
    if lf is None or not trace_id:
        return
    try:
        lf.create_score(
            trace_id=trace_id,
            name=name,
            value=value,
            comment=comment,
        )
    except Exception:
        pass  # scoring must never block the request path


def flush() -> None:
    """Flush buffered events to Langfuse — call before process exit."""
    lf = _get_client()
    if lf is not None:
        try:
            lf.flush()
        except Exception:
            pass
