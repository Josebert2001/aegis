"""Live Model Evaluation and Pipeline Stress-Test for AEGIS Fleet.

Drives the complete assessment-to-credential pipeline against live Gemini models
across the three Room 07 benchmark fixtures (STRONG_PATCH, WEAK_PATCH, INJECTION_PATCH),
running each fixture 3 times to guarantee behavioral stability.
"""

import asyncio
import os
import sys
import time
from typing import Any, Dict, List
from dotenv import load_dotenv

# Load environment
load_dotenv()

from aegis.app import app
from aegis.demo.fixtures import STRONG_PATCH, WEAK_PATCH, INJECTION_PATCH
from aegis.domain import Stage
from aegis.store.repository import get_repository
from aegis.governance.audit import get_audit_log
from fastapi.testclient import TestClient


def run_pipeline_for_fixture(
    client: TestClient,
    fixture_name: str,
    patch_content: str,
    run_index: int,
) -> Dict[str, Any]:
    """Drives the complete pipeline for a single student and submission fixture."""
    student_id = f"std_{fixture_name.lower()}_run{run_index}"
    submission_id = f"sub_{fixture_name.lower()}_run{run_index}"
    name = f"Test Student ({fixture_name} #{run_index})"
    email = f"{student_id}@uniuyo.edu.ng"

    repo = get_repository()
    audit = get_audit_log()

    # 1. Enrol Student
    enrol_resp = client.post(
        "/students/enrol",
        json={
            "student_id": student_id,
            "name": name,
            "email": email,
            "room_id": "room_07_reflected_xss",
        },
    )
    enrol_data = enrol_resp.json()

    # 2. Submit Lab Patch
    sub_resp = client.post(
        "/webhooks/submission_received",
        json={
            "submission_id": submission_id,
            "student_id": student_id,
            "room_id": "room_07_reflected_xss",
            "artifact": patch_content,
        },
    )
    sub_data = sub_resp.json()

    # 3. Collect State & Provenance
    student = repo.get_student(student_id)
    assessment = repo.get_latest_assessment_for_student(student_id)
    verdict = repo.get_latest_verdict_for_student(student_id)
    credential = repo.get_credential_by_student(student_id)
    events = audit.for_subject(student_id)

    # 4. Extract Screening Details
    screen_event = next((e for e in events if e.action == "submission:screen"), None)
    screen_decision = screen_event.payload.get("decision") if screen_event else "UNKNOWN"
    screen_reasons = screen_event.payload.get("reasons", []) if screen_event else []

    return {
        "fixture": fixture_name,
        "run_index": run_index,
        "student_id": student_id,
        "final_stage": student.stage.value if student else "UNKNOWN",
        "screen_decision": screen_decision,
        "screen_reasons": screen_reasons,
        "rubric_score": assessment.score if assessment else None,
        "assessment_passed": assessment.passed if assessment else None,
        "findings": assessment.criteria_met if assessment else [],
        "feedback": assessment.feedback if assessment else "",
        "patch_holds": verdict.exploit_held if verdict else None,
        "breaking_input": verdict.attack_payload if verdict else "",
        "adversary_logs": verdict.logs if verdict else "",
        "credential_issued": credential is not None,
        "trace_id": sub_data.get("trace_id", ""),
        "total_audit_events": len(events),
    }


def evaluate_all_fixtures(runs_per_fixture: int = 3) -> Dict[str, Any]:
    """Runs all three benchmark fixtures multiple times and generates a stability report."""
    client = TestClient(app)

    fixtures = [
        ("STRONG_PATCH", STRONG_PATCH),
        ("WEAK_PATCH", WEAK_PATCH),
        ("INJECTION_PATCH", INJECTION_PATCH),
    ]

    print("=" * 80)
    print("  AEGIS LIVE MODEL PIPELINE EVALUATION & STABILITY SUITE")
    print(f"  Target Models: Registrar/Assessor (gemini-3.7-flash), Adversary (gemini-3.5-flash-lite)")
    print(f"  Runs per fixture: {runs_per_fixture}")
    print("=" * 80)
    print()

    results: Dict[str, List[Dict[str, Any]]] = {}

    for fixture_name, patch_content in fixtures:
        print(f">>> Running 3x evaluations for: {fixture_name}")
        fixture_results = []
        for i in range(1, runs_per_fixture + 1):
            print(f"    - Execution #{i}...", end="", flush=True)
            t0 = time.time()
            res = run_pipeline_for_fixture(client, fixture_name, patch_content, i)
            elapsed = time.time() - t0
            print(f" done in {elapsed:.2f}s (Stage: {res['final_stage']}, Score: {res['rubric_score']}, PatchHolds: {res['patch_holds']})")
            fixture_results.append(res)
        results[fixture_name] = fixture_results
        print()

    # Generate Summary Table
    print("=" * 80)
    print("  PIPELINE EVALUATION SUMMARY & BEHAVIORAL PROOFS")
    print("=" * 80)

    for fixture_name, runs in results.items():
        print(f"\n--- {fixture_name} ---")
        for r in runs:
            idx = r["run_index"]
            score_str = f"{r['rubric_score']}/100" if r['rubric_score'] is not None else "N/A"
            print(f"  Run #{idx}:")
            print(f"    - Egress Gateway Decision: {r['screen_decision']} (Reasons: {r['screen_reasons']})")
            print(f"    - Rubric Score:          {score_str} (Passed: {r['assessment_passed']})")
            print(f"    - Assessor Feedback:     {r['feedback'][:120]}..." if r['feedback'] else "    - Assessor Feedback:     None")
            print(f"    - Adversary Patch Holds: {r['patch_holds']}")
            print(f"    - Breaking Input:        '{r['breaking_input']}'")
            print(f"    - Credential Awarded:    {r['credential_issued']}")
            print(f"    - Provenance Envelopes:  {r['total_audit_events']}")

    return results


if __name__ == "__main__":
    evaluate_all_fixtures(runs_per_fixture=3)
