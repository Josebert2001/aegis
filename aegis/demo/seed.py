"""Multi-Week Time-Compression Harness and ADK Golden-Test Runner.

WHY THIS IS ADK'S GOLDEN-TEST PATTERN, NOT A DEMO CHEAT:
In traditional prompt-chained agents, demonstrating a 3-week workflow requires replaying
hundreds of messages or faking execution history.

In AEGIS, position lives strictly in Python state and cryptographic audit records, not in
replayed conversation history. Because of this architectural invariant, resuming from a
seeded checkpoint executes the EXACT SAME code path as waking up after 3 weeks of real-world
dormancy.

This module provides:
1. Time-compressed simulation of a 21-day student cohort across 8 realistic milestones.
2. Backdated cryptographic audit trails with genuine HMAC-SHA256 signatures.
3. Standalone CLI with `--seed-only` support for zero-network, zero-API-key execution.
"""

import argparse
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid

from aegis.domain import (
    Stage,
    Student,
    Submission,
    Assessment,
    AdversaryVerdict,
    Credential,
    DORMANT_STAGES,
    TRANSITIONS,
    _utcnow_iso,
)
from aegis.governance.identity import (
    REGISTRAR,
    ASSESSOR,
    ADVERSARY,
    ActionEnvelope,
    signed_action,
    SCOPE_STAGE_ADVANCE,
    SCOPE_SUBMISSION_READ,
    SCOPE_ASSESSMENT_WRITE,
    SCOPE_ADVERSARY_RUN,
    SCOPE_CREDENTIAL_ISSUE,
)
from aegis.governance.audit import get_audit_log
from aegis.store.repository import get_repository
from aegis.demo.fixtures import STRONG_PATCH, WEAK_PATCH, INJECTION_PATCH


# -----------------------------------------------------------------------------
# 21-Day Multi-Week Cohort Milestones
# -----------------------------------------------------------------------------

TIMELINE: Dict[str, Dict[str, Any]] = {
    "week0_enrolled": {
        "order": 0,
        "days_ago": 21,
        "stage": Stage.ENROLLED,
        "description": "Student enrols in cohort; awaits initial room assignment.",
    },
    "week1_room_assigned": {
        "order": 1,
        "days_ago": 18,
        "stage": Stage.ROOM_ASSIGNED,
        "description": "Registrar assigns student to Room 07 (Reflected XSS).",
    },
    "week1_awaiting_submission": {
        "order": 2,
        "days_ago": 14,
        "stage": Stage.AWAITING_SUBMISSION,
        "description": "Student is coding the lab fix; fleet agent remains dormant in sleep state.",
    },
    "week2_submission_received": {
        "order": 3,
        "days_ago": 7,
        "stage": Stage.SUBMISSION_RECEIVED,
        "description": "Student submits patch for Room 07; webhook wakes Registrar.",
    },
    "week2_assessed": {
        "order": 4,
        "days_ago": 5,
        "stage": Stage.ASSESSED,
        "description": "Assessor evaluates submission against 100-pt rubric (score: 92/100).",
    },
    "week3_adversary_verified": {
        "order": 5,
        "days_ago": 3,
        "stage": Stage.ADVERSARY_VERIFIED,
        "description": "Adversary attacks patch with 6 attack classes; patch holds.",
    },
    "week3_human_review": {
        "order": 6,
        "days_ago": 2,
        "stage": Stage.HUMAN_REVIEW_PENDING,
        "description": "Flagged for instructor sign-off; agent is dormant awaiting human sign-off webhook.",
    },
    "week3_credential_issued": {
        "order": 7,
        "days_ago": 0,
        "stage": Stage.CREDENTIAL_ISSUED,
        "description": "Verifiable credential issued with full OpenTelemetry reasoning trace ID.",
    },
}


def _backdated_iso(days_ago: int) -> str:
    """Generates an authentic UTC ISO timestamp backdated by N days."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat()


def seed_student_at(
    checkpoint: str,
    student_id: str = "std_arete_demo",
    name: str = "Emeka Okonjo",
    email: str = "emeka.okonjo@uniuyo.edu.ng",
) -> Student:
    """Materializes a student at a specific checkpoint and backdates complete provenance.

    Args:
        checkpoint: One of the TIMELINE milestone keys.
        student_id: Target student identifier.
        name: Student full name.
        email: Student institutional email.

    Returns:
        The materialized Student instance.
    """
    if checkpoint not in TIMELINE:
        valid_keys = list(TIMELINE.keys())
        raise ValueError(f"Unknown checkpoint '{checkpoint}'. Valid options: {valid_keys}")

    target_milestone = TIMELINE[checkpoint]
    target_order = target_milestone["order"]
    target_stage = target_milestone["stage"]
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"

    repo = get_repository()
    audit = get_audit_log()

    # Clear existing state for clean demo determinism
    # Create student at target stage
    student = Student(
        student_id=student_id,
        name=name,
        email=email,
        stage=target_stage,
        room_id="room_07_reflected_xss",
        metadata={"cohort_id": "cohort_arete_2026", "seeded_checkpoint": checkpoint},
        updated_at=_backdated_iso(target_milestone["days_ago"]),
    )
    repo.save_student(student)

    # 1. Step: week0_enrolled
    if target_order >= 0:
        ts0 = _backdated_iso(TIMELINE["week0_enrolled"]["days_ago"])
        env0 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="student:enrol",
            subject=student_id,
            payload={"name": name, "email": email, "room_id": "room_07_reflected_xss"},
            timestamp=ts0,
            trace_id=trace_id,
        ).sign()
        audit.record(env0)

    # 2. Step: week1_room_assigned
    if target_order >= 1:
        ts1 = _backdated_iso(TIMELINE["week1_room_assigned"]["days_ago"])
        env1 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="stage:advance",
            subject=student_id,
            payload={"from_stage": Stage.ENROLLED.value, "to_stage": Stage.ROOM_ASSIGNED.value},
            timestamp=ts1,
            trace_id=trace_id,
        ).sign()
        audit.record(env1)

    # 3. Step: week1_awaiting_submission
    if target_order >= 2:
        ts2 = _backdated_iso(TIMELINE["week1_awaiting_submission"]["days_ago"])
        env2 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="stage:advance",
            subject=student_id,
            payload={"from_stage": Stage.ROOM_ASSIGNED.value, "to_stage": Stage.AWAITING_SUBMISSION.value},
            timestamp=ts2,
            trace_id=trace_id,
        ).sign()
        audit.record(env2)

    # 4. Step: week2_submission_received
    sub_id = f"sub_{student_id}_r07"
    if target_order >= 3:
        ts3 = _backdated_iso(TIMELINE["week2_submission_received"]["days_ago"])
        sub = Submission(
            submission_id=sub_id,
            student_id=student_id,
            room_id="room_07_reflected_xss",
            artifact=STRONG_PATCH,
            submitted_at=ts3,
        )
        repo.save_submission(sub)

        env3 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="webhook:submission_received",
            subject=student_id,
            payload={"submission_id": sub_id, "room_id": "room_07_reflected_xss"},
            timestamp=ts3,
            trace_id=trace_id,
        ).sign()
        audit.record(env3)

    # 5. Step: week2_assessed
    if target_order >= 4:
        ts4 = _backdated_iso(TIMELINE["week2_assessed"]["days_ago"])
        asm = Assessment(
            assessment_id=f"asm_{student_id}_r07",
            submission_id=sub_id,
            student_id=student_id,
            score=92.0,
            passed=True,
            feedback="Excellent contextual output encoding with html.escape.",
            criteria_met=["Vulnerability Identified (30/30)", "Root Cause Fix (30/30)", "No Side Effects (18/20)", "Clear Evidence (14/20)"],
            created_at=ts4,
        )
        repo.save_assessment(asm)

        env4 = ActionEnvelope(
            actor=ASSESSOR.agent_id,
            action="assessment:write",
            subject=student_id,
            payload={"assessment_id": asm.assessment_id, "score": 92.0, "passed": True},
            timestamp=ts4,
            trace_id=trace_id,
        ).sign()
        audit.record(env4)

    # 6. Step: week3_adversary_verified
    if target_order >= 5:
        ts5 = _backdated_iso(TIMELINE["week3_adversary_verified"]["days_ago"])
        verdict = AdversaryVerdict(
            verdict_id=f"vrd_{student_id}_r07",
            submission_id=sub_id,
            student_id=student_id,
            exploit_held=True,
            attack_payload="",
            logs="Attacks: ['boundary', 'double_encoding', 'null_bytes', 'case_variation', 'unicode_norm', 'filter_evasion'] | All defeated.",
            timestamp=ts5,
        )
        repo.save_verdict(verdict)

        env5 = ActionEnvelope(
            actor=ADVERSARY.agent_id,
            action="adversary:run",
            subject=student_id,
            payload={"verdict_id": verdict.verdict_id, "patch_holds": True},
            timestamp=ts5,
            trace_id=trace_id,
        ).sign()
        audit.record(env5)

    # 7. Step: week3_human_review
    if target_order >= 6:
        ts6 = _backdated_iso(TIMELINE["week3_human_review"]["days_ago"])
        env6 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="stage:advance",
            subject=student_id,
            payload={"from_stage": Stage.ADVERSARY_VERIFIED.value, "to_stage": Stage.HUMAN_REVIEW_PENDING.value},
            timestamp=ts6,
            trace_id=trace_id,
        ).sign()
        audit.record(env6)

    # 8. Step: week3_credential_issued
    if target_order >= 7:
        ts7 = _backdated_iso(TIMELINE["week3_credential_issued"]["days_ago"])
        cred = Credential(
            credential_id=f"cred_{student_id}_r07",
            student_id=student_id,
            cohort_id="cohort_arete_2026",
            badge_name="Arete Certified Cybersecurity Practitioner (ACCP)",
            trace_id=trace_id,
            issued_at=ts7,
        )
        repo.save_credential(cred)

        env7 = ActionEnvelope(
            actor=REGISTRAR.agent_id,
            action="credential:issue",
            subject=student_id,
            payload={"credential_id": cred.credential_id, "badge_name": cred.badge_name, "score": 92.0, "trace_id": trace_id},
            timestamp=ts7,
            trace_id=trace_id,
        ).sign()
        audit.record(env7)

    return student


def resume_from(
    checkpoint: str,
    student_id: str = "std_arete_demo",
    seed_only: bool = False,
) -> Dict[str, Any]:
    """Materializes student state and optionally wakes the Registrar to prove seamless resumption."""
    student = seed_student_at(checkpoint=checkpoint, student_id=student_id)
    milestone = TIMELINE[checkpoint]
    days_simulated = 21 - milestone["days_ago"]

    legal_targets = [s.value for s in TRANSITIONS.get(student.stage, set())]
    is_dormant = student.stage in DORMANT_STAGES

    audit = get_audit_log()
    events = audit.for_subject(student_id)
    integrity = audit.verify_chain()

    print("=" * 75)
    print(f"  AEGIS MULTI-WEEK TIME-COMPRESSION HARNESS -- ADK GOLDEN TEST")
    print(f"  Checkpoint:        {checkpoint}")
    print(f"  Simulated Time:    Day {days_simulated} of 21-Day Cohort ({milestone['days_ago']} days ago)")
    print(f"  Student ID:        {student.student_id} ({student.name})")
    print(f"  Assigned Room:     {student.room_id}")
    print(f"  Current Stage:     {student.stage.value}")
    print(f"  Dormancy Status:   {'DORMANT (Waiting for external event)' if is_dormant else 'ACTIVE'}")
    print(f"  Next Legal Stages: {legal_targets or 'None (Terminal Stage)'}")
    print(f"  Audit Provenance:  {len(events)} verifiable signed envelopes (Integrity: {'INTACT' if integrity['intact'] else 'TAMPERED'})")
    print("=" * 75)

    if seed_only:
        print("\n[OK] State seeded successfully (seed-only mode, no API call performed).")
        return {
            "checkpoint": checkpoint,
            "student_id": student.student_id,
            "stage": student.stage.value,
            "days_simulated": days_simulated,
            "days_ago": milestone["days_ago"],
            "is_dormant": is_dormant,
            "legal_targets": legal_targets,
            "events_count": len(events),
            "integrity_intact": integrity["intact"],
        }

    # Live model wake execution
    from aegis.app import _wake
    prompt = (
        f"You have been woken for student {student.name} ({student.student_id}). "
        f"Report your exact position from durable state and name the single next legal action."
    )
    state_delta = {
        "current_stage": student.stage.value,
        "student_id": student.student_id,
        "student_name": student.name,
        "room_id": student.room_id,
        "last_checkpoint_at": student.updated_at,
    }
    print(f"\n[WAKING AGENT via _wake() with state_delta...]")
    agent_response, trace_id = asyncio.run(_wake(student.student_id, prompt, state_delta))
    print(f"Reasoning Trace ID: {trace_id}")
    print(f"Agent Response:\n{agent_response}\n")

    return {
        "checkpoint": checkpoint,
        "student_id": student.student_id,
        "stage": student.stage.value,
        "trace_id": trace_id,
        "agent_response": agent_response,
    }


def main():
    parser = argparse.ArgumentParser(description="AEGIS Multi-Week Time-Compression Harness")
    parser.add_argument(
        "checkpoint",
        nargs="?",
        default="week3_human_review",
        choices=list(TIMELINE.keys()),
        help="Milestone checkpoint to resume from (default: week3_human_review)",
    )
    parser.add_argument(
        "--student-id",
        default="std_arete_demo",
        help="Student identifier (default: std_arete_demo)",
    )
    parser.add_argument(
        "--seed-only",
        action="store_true",
        help="Seed state and print audit provenance without invoking LLM inference",
    )
    args = parser.parse_args()

    resume_from(
        checkpoint=args.checkpoint,
        student_id=args.student_id,
        seed_only=args.seed_only,
    )


if __name__ == "__main__":
    main()
