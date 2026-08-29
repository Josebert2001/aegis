"""AEGIS Governance Plane.

Provides institutional governance for AI agent fleets:
- Least-privilege identity and authorization scopes
- Egress chokepoint gateway with prompt-injection defense and PII redaction
- Cryptographically signed tamper-evident action audit trails
- Central agent registry supporting cross-department discovery and reuse
- OpenTelemetry reasoning trace provenance
"""

from aegis.governance.identity import (
    AgentIdentity,
    ActionEnvelope,
    signed_action,
    REGISTRAR,
    ASSESSOR,
    ADVERSARY,
    SCOPE_SUBMISSION_READ,
    SCOPE_ASSESSMENT_WRITE,
    SCOPE_ADVERSARY_RUN,
    SCOPE_STAGE_ADVANCE,
    SCOPE_CREDENTIAL_ISSUE,
    SCOPE_STUDENT_NOTIFY,
)
from aegis.governance.gateway import (
    Decision,
    GuardResult,
    guard,
    wrap_untrusted,
    redact_pii,
)
from aegis.governance.audit import (
    AuditLog,
    get_audit_log,
)
from aegis.governance.registry import (
    AgentManifest,
    AgentRegistry,
    bootstrap_registry,
    get_agent_registry,
)
from aegis.governance.observability import (
    current_trace_id,
    span,
    cloud_trace_url,
    get_tracer,
)

__all__ = [
    "AgentIdentity",
    "ActionEnvelope",
    "signed_action",
    "REGISTRAR",
    "ASSESSOR",
    "ADVERSARY",
    "SCOPE_SUBMISSION_READ",
    "SCOPE_ASSESSMENT_WRITE",
    "SCOPE_ADVERSARY_RUN",
    "SCOPE_STAGE_ADVANCE",
    "SCOPE_CREDENTIAL_ISSUE",
    "SCOPE_STUDENT_NOTIFY",
    "Decision",
    "GuardResult",
    "guard",
    "wrap_untrusted",
    "redact_pii",
    "AuditLog",
    "get_audit_log",
    "AgentManifest",
    "AgentRegistry",
    "bootstrap_registry",
    "get_agent_registry",
    "current_trace_id",
    "span",
    "cloud_trace_url",
    "get_tracer",
]
