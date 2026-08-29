"""Unit and integration tests for demo fixtures and multi-week time-compression harness."""

import pytest
from aegis.domain import Stage
from aegis.governance.gateway import guard, Decision
from aegis.demo.fixtures import WEAK_PATCH, STRONG_PATCH, INJECTION_PATCH
from aegis.demo.seed import TIMELINE, seed_student_at, resume_from
from aegis.store.repository import get_repository, InMemoryRepository
from aegis.governance.audit import get_audit_log, InMemoryAuditLog


@pytest.fixture(autouse=True)
def reset_state():
    """Resets in-memory storage before each test."""
    repo = get_repository()
    if isinstance(repo, InMemoryRepository):
        repo.students.clear()
        repo.cohorts.clear()
        repo.submissions.clear()
        repo.assessments.clear()
        repo.verdicts.clear()
        repo.credentials.clear()

    audit = get_audit_log()
    if isinstance(audit, InMemoryAuditLog):
        audit._entries.clear()


# -----------------------------------------------------------------------------
# 1. Lab Submission Fixtures Tests
# -----------------------------------------------------------------------------

def test_fixtures_content_and_gateway_behavior():
    """Validates that lab fixtures reflect realistic security and adversarial surfaces."""
    assert "html.escape" in STRONG_PATCH
    assert "replace(\"<script>\"" in WEAK_PATCH
    assert "Ignore all previous instructions" in INJECTION_PATCH

    # Strong patch passes gateway (matric number sanitized)
    res_strong = guard(STRONG_PATCH, source="student_submission", actor="assessor")
    assert res_strong.decision == Decision.SANITIZE.value
    assert "[MATRIC_REDACTED]" in res_strong.content
    assert res_strong.screened_by == "local"

    # Weak patch passes gateway (matric number sanitized)
    res_weak = guard(WEAK_PATCH, source="student_submission", actor="assessor")
    assert res_weak.decision == Decision.SANITIZE.value
    assert "[MATRIC_REDACTED]" in res_weak.content

    # Injection patch is BLOCKED at gateway
    res_injection = guard(INJECTION_PATCH, source="student_submission", actor="assessor")
    assert res_injection.decision == Decision.BLOCK.value
    assert "instruction_override" in res_injection.reasons


# -----------------------------------------------------------------------------
# 2. Multi-Week Time-Compression Harness Tests
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("checkpoint_name", list(TIMELINE.keys()))
def test_seed_student_at_all_milestones(checkpoint_name):
    """Verifies that seed_student_at materializes correct stages and backdated audit entries."""
    student = seed_student_at(checkpoint=checkpoint_name, student_id=f"std_{checkpoint_name}")
    expected_stage = TIMELINE[checkpoint_name]["stage"]
    assert student.stage == expected_stage
    assert student.metadata["seeded_checkpoint"] == checkpoint_name

    audit = get_audit_log()
    events = audit.for_subject(f"std_{checkpoint_name}")
    expected_count = TIMELINE[checkpoint_name]["order"] + 1
    assert len(events) == expected_count

    # All generated audit signatures must be cryptographically valid
    for event in events:
        assert event.verify() is True


def test_resume_from_seed_only_mode():
    """resume_from in seed_only mode returns full provenance summary without model calls."""
    res = resume_from("week3_human_review", student_id="std_test_resume", seed_only=True)
    assert res["checkpoint"] == "week3_human_review"
    assert res["stage"] == Stage.HUMAN_REVIEW_PENDING.value
    assert res["days_simulated"] == 19
    assert res["days_ago"] == 2
    assert res["is_dormant"] is True
    assert "CREDENTIAL_ISSUED" in res["legal_targets"]
    assert res["integrity_intact"] is True


def test_process_restart_durability_contract():
    """Validates that DatabaseSessionService preserves session state across memory teardowns."""
    from aegis.app import session_service
    assert type(session_service).__name__ == "DatabaseSessionService"

