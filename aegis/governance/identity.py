"""Agent Identity, Authorization Scopes, and Cryptographic Action Envelopes.

Architectural Rules:
1. AUTHORIZATION IS A PYTHON SCOPE CHECK THAT RUNS BEFORE THE ACTION.
   Never an instruction telling a model what it may not do. A jailbroken
   agent must still be unable to escalate.
2. LEAST PRIVILEGE, AND THE AGENT FACING HOSTILE INPUT IS THE LEAST PRIVILEGED.
   The Assessor reads attacker-authored text, so it gets submission:read and
   assessment:write and NOTHING ELSE. It cannot issue credentials. A successful
   injection against it buys the attacker nothing.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from typing import Any, Dict, FrozenSet, Optional, Union

from aegis.config import settings

# Canonical Scope Constants
SCOPE_SUBMISSION_READ: str = "submission:read"
SCOPE_ASSESSMENT_WRITE: str = "assessment:write"
SCOPE_ADVERSARY_RUN: str = "adversary:run"
SCOPE_STAGE_ADVANCE: str = "stage:advance"
SCOPE_CREDENTIAL_ISSUE: str = "credential:issue"
SCOPE_STUDENT_NOTIFY: str = "student:notify"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_signing_key(override_key: Optional[Union[str, bytes]] = None) -> bytes:
    """Resolves the HMAC secret key from argument, environment, or settings."""
    if override_key is not None:
        if isinstance(override_key, str):
            return override_key.encode("utf-8")
        return override_key

    env_key = os.getenv("AEGIS_HMAC_SECRET", settings.hmac_secret_key)
    return env_key.encode("utf-8")


@dataclass(frozen=True)
class AgentIdentity:
    """Immutable identity and cryptographic authority for an institutional agent."""

    agent_id: str
    display_name: str
    service_account: str
    scopes: FrozenSet[str]
    version: str = "1.0.0"

    def can(self, scope: str) -> bool:
        """Checks if this agent identity holds the specified permission scope."""
        return scope in self.scopes

    def require(self, scope: str) -> None:
        """Enforces that this agent identity possesses the required permission scope.

        Raises:
            PermissionError: If the agent lacks the required scope.
        """
        if not self.can(scope):
            held = sorted(list(self.scopes))
            raise PermissionError(
                f"Agent '{self.agent_id}' ({self.display_name}) lacks required scope '{scope}'. "
                f"Held scopes: {held}"
            )


# Pre-configured institutional fleet identities
REGISTRAR = AgentIdentity(
    agent_id="registrar",
    display_name="AEGIS Registrar Agent",
    service_account="aegis-registrar@arete-aegis.iam.gserviceaccount.com",
    scopes=frozenset({
        SCOPE_STAGE_ADVANCE,
        SCOPE_CREDENTIAL_ISSUE,
        SCOPE_STUDENT_NOTIFY,
        SCOPE_SUBMISSION_READ,
    }),
    version="1.0.0",
)

ASSESSOR = AgentIdentity(
    agent_id="assessor",
    display_name="AEGIS Lab Assessor Agent",
    service_account="aegis-assessor@arete-aegis.iam.gserviceaccount.com",
    # Deliberately minimal: Assessor faces hostile, attacker-authored text.
    # It cannot advance stages, issue credentials, or notify students.
    scopes=frozenset({
        SCOPE_SUBMISSION_READ,
        SCOPE_ASSESSMENT_WRITE,
    }),
    version="1.0.0",
)

ADVERSARY = AgentIdentity(
    agent_id="adversary",
    display_name="AEGIS Adversary Verification Agent",
    service_account="aegis-adversary@arete-aegis.iam.gserviceaccount.com",
    scopes=frozenset({
        SCOPE_SUBMISSION_READ,
        SCOPE_ADVERSARY_RUN,
    }),
    version="1.0.0",
)


@dataclass
class ActionEnvelope:
    """Cryptographically signed, tamper-evident action provenance record."""

    actor: str
    action: str
    subject: str
    payload: Dict[str, Any]
    timestamp: str = field(default_factory=_utcnow_iso)
    trace_id: str = ""
    signature: str = ""

    def compute_payload_sha256(self) -> str:
        """Generates deterministic SHA-256 hash of payload content."""
        canonical_json = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def compute_signature(self, secret_key: Optional[Union[str, bytes]] = None) -> str:
        """Calculates HMAC-SHA256 signature across canonical envelope metadata + payload hash."""
        key = _get_signing_key(secret_key)
        canonical_struct = {
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "timestamp": self.timestamp,
            "trace_id": self.trace_id,
            "payload_sha256": self.compute_payload_sha256(),
        }
        canonical_bytes = json.dumps(canonical_struct, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(key, canonical_bytes, hashlib.sha256).hexdigest()

    def sign(self, secret_key: Optional[Union[str, bytes]] = None) -> "ActionEnvelope":
        """Signs the envelope in-place and returns self."""
        self.signature = self.compute_signature(secret_key)
        return self

    def verify(self, secret_key: Optional[Union[str, bytes]] = None) -> bool:
        """Verifies signature integrity. Returns False if payload or metadata was tampered with."""
        if not self.signature:
            return False
        expected = self.compute_signature(secret_key)
        return hmac.compare_digest(self.signature, expected)


def signed_action(
    identity: AgentIdentity,
    action: str,
    subject: str,
    required_scope: str,
    payload: Dict[str, Any],
    trace_id: str = "",
    secret_key: Optional[Union[str, bytes]] = None,
) -> ActionEnvelope:
    """Authorizes an action against agent scope, then returns a signed ActionEnvelope.

    Hard rule: Authorization check is executed FIRST in Python before signing/execution.
    """
    # 1. Python-level pre-action scope enforcement
    identity.require(required_scope)

    # 2. Construct envelope
    envelope = ActionEnvelope(
        actor=identity.agent_id,
        action=action,
        subject=subject,
        payload=payload,
        timestamp=_utcnow_iso(),
        trace_id=trace_id,
    )

    # 3. Cryptographically sign envelope
    envelope.sign(secret_key)
    return envelope
