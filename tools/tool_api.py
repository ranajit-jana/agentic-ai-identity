"""
Phase 2 — Tool API (no auth yet).

Three tools exposed as plain HTTP endpoints.
Auth + policy will be enforced by the gateway in Phase 4.

Run:
    uv run uvicorn tools.tool_api:app --port 8000 --reload
"""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Tool API", version="1.0.0")


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class WeatherRequest(BaseModel):
    city: str

class WeatherResponse(BaseModel):
    city: str
    temperature_c: float
    condition: str


class CalculatorRequest(BaseModel):
    operation: str          # add | subtract | multiply | divide
    a: float
    b: float

class CalculatorResponse(BaseModel):
    operation: str
    a: float
    b: float
    result: float


class AdminRequest(BaseModel):
    action: str             # list_agents | revoke_cert | rotate_keys

class AdminResponse(BaseModel):
    action: str
    status: str
    detail: str


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@app.post("/tool/weather", response_model=WeatherResponse)
def weather(req: WeatherRequest):
    # Stubbed — returns dummy data so we can focus on the auth layer
    stubs = {
        "london":  {"temperature_c": 12.0, "condition": "cloudy"},
        "delhi":   {"temperature_c": 38.0, "condition": "sunny"},
        "new york":{"temperature_c": 22.0, "condition": "partly cloudy"},
    }
    data = stubs.get(req.city.lower(), {"temperature_c": 20.0, "condition": "unknown"})
    return WeatherResponse(city=req.city, **data)


@app.post("/tool/calculator", response_model=CalculatorResponse)
def calculator(req: CalculatorRequest):
    ops = {
        "add":      req.a + req.b,
        "subtract": req.a - req.b,
        "multiply": req.a * req.b,
        "divide":   req.a / req.b if req.b != 0 else float("nan"),
    }
    if req.operation not in ops:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown operation '{req.operation}'. Use: {list(ops)}")
    return CalculatorResponse(operation=req.operation, a=req.a, b=req.b, result=ops[req.operation])


@app.post("/tool/admin", response_model=AdminResponse)
def admin(req: AdminRequest):
    # Sensitive tool — only privileged agents should reach this (enforced in Phase 4)
    actions = {
        "list_agents":  "returned agent roster",
        "revoke_cert":  "cert revocation queued",
        "rotate_keys":  "key rotation initiated",
    }
    if req.action not in actions:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Unknown action '{req.action}'. Use: {list(actions)}")
    return AdminResponse(action=req.action, status="ok", detail=actions[req.action])


@app.get("/health")
def health():
    return {"status": "ok"}
