"""Aegis Domain State Machine and Core Entities.

Hard architectural rule:
The state machine lives in Python, not in a prompt. An LLM asked to track
its own position across three weeks will hallucinate progress. The model
decides WHAT TO DO NEXT; code decides WHAT IS LEGAL. Validate every
transition and reject illegal ones outright.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set


class Stage(str, Enum):
    """The ordered lifecycle stages for a student within a cohort."""

    ENROLLED = "ENROLLED"
    ROOM_ASSIGNED = "ROOM_ASSIGNED"
    AWAITING_SUBMISSION = "AWAITING_SUBMISSION"
    SUBMISSION_RECEIVED = "SUBMISSION_RECEIVED"
    ASSESSED = "ASSESSED"
    ADVERSARY_VERIFIED = "ADVERSARY_VERIFIED"
    HUMAN_REVIEW_PENDING = "HUMAN_REVIEW_PENDING"
    CREDENTIAL_ISSUED = "CREDENTIAL_ISSUED"
    FAILED_NEEDS_RESUBMIT = "FAILED_NEEDS_RESUBMIT"
    WITHDRAWN = "WITHDRAWN"


# Stages where agents remain dormant; only external webhooks/signals wake them.
DORMANT_STAGES: Set[Stage] = {
    Stage.AWAITING_SUBMISSION,
    Stage.HUMAN_REVIEW_PENDING,
}

# Explicit deterministic transition map.
# Any transition not listed here is illegal and will be rejected in code.
TRANSITIONS: Dict[Stage, Set[Stage]] = {
    Stage.ENROLLED: {Stage.ROOM_ASSIGNED, Stage.WITHDRAWN},
    Stage.ROOM_ASSIGNED: {Stage.AWAITING_SUBMISSION, Stage.WITHDRAWN},
    Stage.AWAITING_SUBMISSION: {Stage.SUBMISSION_RECEIVED, Stage.WITHDRAWN},
    Stage.SUBMISSION_RECEIVED: {
        Stage.ASSESSED,
        Stage.FAILED_NEEDS_RESUBMIT,
        Stage.WITHDRAWN,
    },
    Stage.ASSESSED: {
        Stage.ADVERSARY_VERIFIED,
        Stage.HUMAN_REVIEW_PENDING,
        Stage.FAILED_NEEDS_RESUBMIT,
        Stage.WITHDRAWN,
    },
    Stage.ADVERSARY_VERIFIED: {
        Stage.CREDENTIAL_ISSUED,
        Stage.HUMAN_REVIEW_PENDING,
        Stage.FAILED_NEEDS_RESUBMIT,
        Stage.WITHDRAWN,
    },
    Stage.HUMAN_REVIEW_PENDING: {
        Stage.CREDENTIAL_ISSUED,
        Stage.FAILED_NEEDS_RESUBMIT,
        Stage.WITHDRAWN,
    },
    Stage.FAILED_NEEDS_RESUBMIT: {
        Stage.AWAITING_SUBMISSION,
        Stage.WITHDRAWN,
    },
    Stage.CREDENTIAL_ISSUED: set(),  # Terminal
    Stage.WITHDRAWN: set(),          # Terminal
}


class IllegalTransition(Exception):
    """Raised when an illegal lifecycle transition is attempted."""

    def __init__(self, current: Stage, target: Stage, legal_targets: Set[Stage]):
        legal_names = ", ".join(sorted(s.value for s in legal_targets)) or "none (terminal stage)"
        super().__init__(
            f"Illegal transition from '{current.value}' to '{target.value}'. "
            f"Legal next stages: [{legal_names}]"
        )
        self.current = current
        self.target = target
        self.legal_targets = legal_targets


def assert_transition(current: Stage, target: Stage) -> None:
    """Validates that a stage transition is allowed according to the FSM.

    Raises:
        IllegalTransition: If the transition is not in the legal TRANSITIONS set.
    """
    legal_targets = TRANSITIONS.get(current, set())
    if target not in legal_targets:
        raise IllegalTransition(current=current, target=target, legal_targets=legal_targets)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Student:
    """Student profile and active cohort progress state."""

    student_id: str
    name: str
    email: str
    stage: Stage = Stage.ENROLLED
    room_id: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    updated_at: str = field(default_factory=_utcnow_iso)


@dataclass
class Cohort:
    """Cybersecurity training cohort."""

    cohort_id: str
    name: str
    students: Dict[str, Student] = field(default_factory=dict)
    created_at: str = field(default_factory=_utcnow_iso)


@dataclass
class Submission:
    """Student lab submission.

    WARNING: The `artifact` field contains untrusted, potentially hostile
    attacker-authored exploit code, evasion payloads, or patch scripts
    submitted as part of cybersecurity 'Build It. Break It. Secure It.' labs.
    This content must NEVER be trusted or executed unsafely.
    """

    submission_id: str
    student_id: str
    room_id: str
    artifact: str  # Untrusted / hostile input surface
    submitted_at: str = field(default_factory=_utcnow_iso)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class Assessment:
    """Automated rubric and security evaluation by the Assessor agent."""

    assessment_id: str
    submission_id: str
    student_id: str
    score: float
    passed: bool
    feedback: str
    criteria_met: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=_utcnow_iso)


@dataclass
class AdversaryVerdict:
    """Adversarial stress-test result by the Adversary agent."""

    verdict_id: str
    submission_id: str
    student_id: str
    exploit_held: bool  # True if student patch defeated the adversarial attack
    attack_payload: str
    logs: str
    timestamp: str = field(default_factory=_utcnow_iso)


@dataclass
class Credential:
    """Tamper-evident verifiable credential awarded upon cohort completion.

    The `trace_id` links this credential directly to the OpenTelemetry trace
    documenting the complete autonomous multi-agent reasoning chain.
    """

    credential_id: str
    student_id: str
    cohort_id: str
    badge_name: str
    trace_id: str  # OpenTelemetry trace ID of the reasoning chain
    issued_at: str = field(default_factory=_utcnow_iso)
    signature: Optional[str] = None
