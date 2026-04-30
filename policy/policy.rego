package authz

import rego.v1

# ---------------------------------------------------------------------------
# Tool access — can this agent call this tool?
# ---------------------------------------------------------------------------

default allow := false

# ---------------------------------------------------------------------------
# Exfiltration detection — checked inside allow so it takes priority
# ---------------------------------------------------------------------------

exfiltration_attempt if {
    contains(lower(input.params.query), "bearer")
}

exfiltration_attempt if {
    contains(lower(input.params.query), "authorization")
}

# ---------------------------------------------------------------------------
# Tool access — can this agent call this tool?
# ---------------------------------------------------------------------------

# Non-delegated call — direct agent identity only
allow if {
    data.roles[input.agent_id] == input.role
    input.tool in data.allowed_tools[input.role]
    not is_delegated
    not exfiltration_attempt
}

# Delegated call — must satisfy BOTH role scope AND delegation scope
allow if {
    data.roles[input.agent_id] == input.role
    input.tool in data.allowed_tools[input.role]
    input.tool in input.delegation_scope
    is_delegated
    input.delegation_depth <= 2
    not exfiltration_attempt
}

is_delegated if {
    input.delegated_by != ""
}

# ---------------------------------------------------------------------------
# Agent communication — can agent A send a message to agent B?
# ---------------------------------------------------------------------------

default allow_message := false

allow_message if {
    data.agent_trust[input.to_agent][input.from_agent] == "trusted"
}
