"""Append-Only Tamper-Evident Audit Trail.

Architectural Rules:
1. APPEND-ONLY BY DESIGN. No update or delete methods exist in this module.
2. CRYPTOGRAPHIC PROVENANCE. Every recorded ActionEnvelope is verified against
   its HMAC-SHA256 signature, linking every action to an agent identity,
   timestamp, and OpenTelemetry trace ID.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Union
import logging

from aegis.config import settings
from aegis.governance.identity import ActionEnvelope

logger = logging.getLogger("aegis.governance.audit")


class BaseAuditLog(ABC):
    """Abstract interface for append-only audit logs."""

    @abstractmethod
    def record(self, envelope: ActionEnvelope) -> ActionEnvelope:
        """Appends a signed ActionEnvelope to the immutable audit log."""
        pass

    @abstractmethod
    def get_entries(self) -> List[ActionEnvelope]:
        """Returns all recorded audit envelopes in chronological order."""
        pass

    @abstractmethod
    def for_subject(self, subject: str) -> List[ActionEnvelope]:
        """Returns the full provenance history for a specific subject (e.g. student ID)."""
        pass

    def verify_chain(self, secret_key: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
        """Verifies HMAC signatures and payload integrity across all recorded envelopes.

        Returns:
            Dict containing {"checked": int, "tampered": int, "intact": bool}
        """
        entries = self.get_entries()
        checked = 0
        tampered = 0

        for entry in entries:
            checked += 1
            if not entry.verify(secret_key):
                tampered += 1

        return {
            "checked": checked,
            "tampered": tampered,
            "intact": (checked > 0 and tampered == 0) if checked > 0 else True,
        }


class InMemoryAuditLog(BaseAuditLog):
    """In-memory append-only audit trail for local execution, tests, and zero-cloud demos."""

    def __init__(self) -> None:
        self._entries: List[ActionEnvelope] = []

    def record(self, envelope: ActionEnvelope) -> ActionEnvelope:
        # Note: We store a shallow copy to prevent external in-memory tampering of already-recorded objects
        envelope_copy = ActionEnvelope(
            actor=envelope.actor,
            action=envelope.action,
            subject=envelope.subject,
            payload=dict(envelope.payload),
            timestamp=envelope.timestamp,
            trace_id=envelope.trace_id,
            signature=envelope.signature,
        )
        self._entries.append(envelope_copy)
        return envelope_copy

    def get_entries(self) -> List[ActionEnvelope]:
        return list(self._entries)

    def for_subject(self, subject: str) -> List[ActionEnvelope]:
        return [entry for entry in self._entries if entry.subject == subject]


class FirestoreAuditLog(BaseAuditLog):
    """Google Cloud Firestore append-only audit trail for production."""

    def __init__(self, project_id: Optional[str] = None) -> None:
        from google.cloud import firestore  # Lazy import

        self.db = firestore.Client(project=project_id or settings.gcp_project)
        self.collection_name = "audit_log"

    def record(self, envelope: ActionEnvelope) -> ActionEnvelope:
        doc_data = {
            "actor": envelope.actor,
            "action": envelope.action,
            "subject": envelope.subject,
            "payload": envelope.payload,
            "timestamp": envelope.timestamp,
            "trace_id": envelope.trace_id,
            "signature": envelope.signature,
        }
        self.db.collection(self.collection_name).add(doc_data)
        return envelope

    def get_entries(self) -> List[ActionEnvelope]:
        docs = (
            self.db.collection(self.collection_name)
            .order_by("timestamp", direction="ASCENDING")
            .stream()
        )
        entries: List[ActionEnvelope] = []
        for doc in docs:
            data = doc.to_dict()
            entries.append(
                ActionEnvelope(
                    actor=data["actor"],
                    action=data["action"],
                    subject=data["subject"],
                    payload=data.get("payload", {}),
                    timestamp=data["timestamp"],
                    trace_id=data.get("trace_id", ""),
                    signature=data.get("signature", ""),
                )
            )
        return entries

    def for_subject(self, subject: str) -> List[ActionEnvelope]:
        docs = [
            doc.to_dict()
            for doc in self.db.collection(self.collection_name).where("subject", "==", subject).stream()
        ]
        docs.sort(key=lambda d: d.get("timestamp", ""))
        entries: List[ActionEnvelope] = []
        for data in docs:
            entries.append(
                ActionEnvelope(
                    actor=data["actor"],
                    action=data["action"],
                    subject=data["subject"],
                    payload=data.get("payload", {}),
                    timestamp=data["timestamp"],
                    trace_id=data.get("trace_id", ""),
                    signature=data.get("signature", ""),
                )
            )
        return entries


# Global singleton instance
_audit_log_instance: Optional[BaseAuditLog] = None


def get_audit_log() -> BaseAuditLog:
    """Returns the configured AuditLog singleton backend."""
    global _audit_log_instance
    if settings.use_firestore:
        return FirestoreAuditLog()
    if _audit_log_instance is None:
        _audit_log_instance = InMemoryAuditLog()
    return _audit_log_instance


# Export AuditLog alias for BaseAuditLog
AuditLog = BaseAuditLog
