package authz

import rego.v1

# ---------------------------------------------------------------------------
# Tool access — can this agent call this tool?
#
# Two separate allow rules handle the delegated and non-delegated cases.
# In Rego, multiple `allow` rules are OR-ed together, so both rules are
# evaluated. We keep them separate because the conditions are mutually
# exclusive: a call is either delegated (delegated_by != "") or it isn't.
# ---------------------------------------------------------------------------

# Default: deny everything unless an allow rule explicitly matches
default allow := false

# ---------------------------------------------------------------------------
# Exfiltration detection — checked inside both allow rules via `not`
#
# If the agent tries to pass credential keywords in params (e.g. asking a tool
# to "search for bearer token abc"), the call is denied regardless of role.
# This prevents an LLM from being tricked into leaking its own credentials
# through a seemingly innocent tool call.
# ---------------------------------------------------------------------------

exfiltration_attempt if {
    contains(lower(input.params.query), "bearer")
}

exfiltration_attempt if {
    contains(lower(input.params.query), "authorization")
}

# ---------------------------------------------------------------------------
# Non-delegated call — agent acts on its own direct identity
#
# All four conditions must hold:
#   1. The agent's registered role matches what it claims in the JWT
#   2. The requested tool is in that role's allowed tool list
#   3. This is NOT a delegated call (avoids dual-matching with the rule below)
#   4. No exfiltration keywords in the request params
# ---------------------------------------------------------------------------

allow if {
    data.roles[input.agent_id] == input.role          # role claim matches registered role
    input.tool in data.allowed_tools[input.role]      # tool is in role's allowed list
    not is_delegated                                   # direct identity, not acting for someone else
    not exfiltration_attempt
}

# ---------------------------------------------------------------------------
# Delegated call — agent acts within a scope granted by a supervisor
#
# A sub-agent can only call tools that appear in BOTH:
#   - Its own role's allowed_tools   (role-level ceiling)
#   - The delegation_scope from the supervisor's JWT  (delegation ceiling)
#
# The delegation_depth limit (<=2) prevents unbounded chains:
#   supervisor → sub-agent → sub-sub-agent is allowed
#   going deeper is denied here and also prevented in identity/delegator.py
# ---------------------------------------------------------------------------

allow if {
    data.roles[input.agent_id] == input.role
    input.tool in data.allowed_tools[input.role]
    input.tool in input.delegation_scope              # must also be within granted scope
    is_delegated
    input.delegation_depth <= 2                       # max chain depth
    not exfiltration_attempt
}

# Helper: true when this request was issued by a sub-agent acting under delegation
is_delegated if {
    input.delegated_by != ""
}

# ---------------------------------------------------------------------------
# Agent communication — can agent A send a message to agent B?
#
# The trust map in data.json is direction-specific:
#   agent_trust[to_agent][from_agent] == "trusted"
# means "to_agent trusts messages from from_agent".
#
# A cert-issued agent that isn't explicitly trusted is silently dropped —
# having a valid cert proves identity, not intent.
# ---------------------------------------------------------------------------

default allow_message := false

allow_message if {
    data.agent_trust[input.to_agent][input.from_agent] == "trusted"
}
