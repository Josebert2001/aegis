"""Tests for domain state machine, FSM invariants, and repository transitions."""

import pytest
from aegis.domain import (
    Stage,
    TRANSITIONS,
    DORMANT_STAGES,
    IllegalTransition,
    assert_transition,
    Student,
    Submission,
    Assessment,
    AdversaryVerdict,
    Credential,
)
from aegis.store.repository import InMemoryRepository


def test_dormant_stages_definition():
    """Verify dormant stages where agents sleep awaiting external webhook signals."""
    assert Stage.AWAITING_SUBMISSION in DORMANT_STAGES
    assert Stage.HUMAN_REVIEW_PENDING in DORMANT_STAGES
    assert len(DORMANT_STAGES) == 2


def test_happy_path_walkable():
    """Verify the complete standard lifecycle from ENROLLED to CREDENTIAL_ISSUED."""
    repo = InMemoryRepository()
    student = Student(student_id="std-101", name="Ada Lovelace", email="ada@arete.edu")
    repo.save_student(student)
    assert student.stage == Stage.ENROLLED

    # 1. ENROLLED -> ROOM_ASSIGNED
    student = repo.advance("std-101", Stage.ROOM_ASSIGNED)
    assert student.stage == Stage.ROOM_ASSIGNED

    # 2. ROOM_ASSIGNED -> AWAITING_SUBMISSION
    student = repo.advance("std-101", Stage.AWAITING_SUBMISSION)
    assert student.stage == Stage.AWAITING_SUBMISSION

    # 3. AWAITING_SUBMISSION -> SUBMISSION_RECEIVED
    student = repo.advance("std-101", Stage.SUBMISSION_RECEIVED)
    assert student.stage == Stage.SUBMISSION_RECEIVED

    # 4. SUBMISSION_RECEIVED -> ASSESSED
    student = repo.advance("std-101", Stage.ASSESSED)
    assert student.stage == Stage.ASSESSED

    # 5. ASSESSED -> ADVERSARY_VERIFIED
    student = repo.advance("std-101", Stage.ADVERSARY_VERIFIED)
    assert student.stage == Stage.ADVERSARY_VERIFIED

    # 6. ADVERSARY_VERIFIED -> CREDENTIAL_ISSUED
    student = repo.advance("std-101", Stage.CREDENTIAL_ISSUED)
    assert student.stage == Stage.CREDENTIAL_ISSUED


@pytest.mark.parametrize(
    "current,illegal_target",
    [
        (Stage.ENROLLED, Stage.CREDENTIAL_ISSUED),
        (Stage.AWAITING_SUBMISSION, Stage.ASSESSED),
        (Stage.CREDENTIAL_ISSUED, Stage.ENROLLED),
        (Stage.CREDENTIAL_ISSUED, Stage.ROOM_ASSIGNED),
        (Stage.WITHDRAWN, Stage.ENROLLED),
        (Stage.WITHDRAWN, Stage.CREDENTIAL_ISSUED),
        (Stage.ENROLLED, Stage.ASSESSED),
        (Stage.ROOM_ASSIGNED, Stage.CREDENTIAL_ISSUED),
    ],
)
def test_illegal_transitions_rejected(current: Stage, illegal_target: Stage):
    """Verify that jumping stages or resurrecting terminal stages is strictly rejected in Python."""
    with pytest.raises(IllegalTransition) as exc_info:
        assert_transition(current, illegal_target)
    assert f"Illegal transition from '{current.value}' to '{illegal_target.value}'" in str(exc_info.value)


def test_repository_enforces_illegal_transition():
    """Verify the repository fails to mutate state when an illegal transition is attempted."""
    repo = InMemoryRepository()
    student = Student(student_id="std-102", name="Alan Turing", email="alan@arete.edu")
    repo.save_student(student)

    # Attempt illegal skip: ENROLLED -> CREDENTIAL_ISSUED
    with pytest.raises(IllegalTransition):
        repo.advance("std-102", Stage.CREDENTIAL_ISSUED)

    # Verify student state was not corrupted
    saved = repo.get_student("std-102")
    assert saved is not None
    assert saved.stage == Stage.ENROLLED


def test_failed_needs_resubmit_loop():
    """Verify failure states can loop back to AWAITING_SUBMISSION from various stages."""
    repo = InMemoryRepository()
    student = Student(student_id="std-103", name="Grace Hopper", email="grace@arete.edu")
    repo.save_student(student)

    repo.advance("std-103", Stage.ROOM_ASSIGNED)
    repo.advance("std-103", Stage.AWAITING_SUBMISSION)
    repo.advance("std-103", Stage.SUBMISSION_RECEIVED)

    # Failure at submission review -> FAILED_NEEDS_RESUBMIT -> AWAITING_SUBMISSION
    repo.advance("std-103", Stage.FAILED_NEEDS_RESUBMIT)
    assert repo.get_student("std-103").stage == Stage.FAILED_NEEDS_RESUBMIT

    repo.advance("std-103", Stage.AWAITING_SUBMISSION)
    assert repo.get_student("std-103").stage == Stage.AWAITING_SUBMISSION


def test_human_review_path():
    """Verify edge case routing through human review."""
    repo = InMemoryRepository()
    student = Student(student_id="std-104", name="Margaret Hamilton", email="margaret@arete.edu")
    repo.save_student(student)

    repo.advance("std-104", Stage.ROOM_ASSIGNED)
    repo.advance("std-104", Stage.AWAITING_SUBMISSION)
    repo.advance("std-104", Stage.SUBMISSION_RECEIVED)
    repo.advance("std-104", Stage.ASSESSED)
    repo.advance("std-104", Stage.HUMAN_REVIEW_PENDING)
    assert repo.get_student("std-104").stage == Stage.HUMAN_REVIEW_PENDING

    repo.advance("std-104", Stage.CREDENTIAL_ISSUED)
    assert repo.get_student("std-104").stage == Stage.CREDENTIAL_ISSUED


def test_credential_dataclass_trace_id():
    """Verify Credential dataclass carries the mandatory trace_id."""
    cred = Credential(
        credential_id="cred-001",
        student_id="std-101",
        cohort_id="cohort-fall-26",
        badge_name="Arete Certified Defensive Practitioner",
        trace_id="4bf92f3577b34da6a3ce929d0e0e4736",
    )
    assert cred.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert cred.student_id == "std-101"
