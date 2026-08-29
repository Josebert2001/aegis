"""Integration tests for AEGIS FastAPI application and HTTP endpoints."""

import pytest
from fastapi.testclient import TestClient

from aegis.app import app
from aegis.domain import Stage, Student, Submission, Assessment, AdversaryVerdict, Credential
from aegis.store.repository import get_repository, InMemoryRepository
from aegis.governance.audit import get_audit_log, InMemoryAuditLog


@pytest.fixture
def client():
    """Returns FastAPI test client."""
    return TestClient(app)


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
# 1. Health & Config Endpoints
# -----------------------------------------------------------------------------

def test_health_endpoint(client):
    """GET /health returns runtime settings without model calls."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "aegis-fleet"
    assert "models" in data
    assert data["models"]["registrar"] == "gemini-3.7-flash"
    assert data["models"]["assessor"] == "gemini-3.7-flash"
    assert data["models"]["adversary"] == "gemini-3.5-flash-lite"
    assert "cloud_flags" in data


# -----------------------------------------------------------------------------
# 2. Registry Discovery Endpoints
# -----------------------------------------------------------------------------

def test_registry_endpoint(client):
    """GET /registry returns registered manifests and supports filtering."""
    # List all
    resp = client.get("/registry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 3

    # Filter by capability and authorized department
    filtered_resp = client.get(
        "/registry?capability=security_lab_assessment&department=UniUyo+Data+Science"
    )
    assert filtered_resp.status_code == 200
    filtered_data = filtered_resp.json()
    assert filtered_data["count"] == 1
    assert filtered_data["agents"][0]["agent_id"] == "assessor"


# -----------------------------------------------------------------------------
# 3. Student Enrollment & Webhooks
# -----------------------------------------------------------------------------

def test_enrol_student_endpoint(client):
    """POST /students/enrol saves student, signs audit envelope, and wakes registrar."""
    payload = {
        "student_id": "21/CY1089",
        "name": "Emeka Okonjo",
        "email": "emeka@uniuyo.edu.ng",
        "room_id": "room_01_sqli",
        "metadata": {"cohort": "2026_alpha"},
    }
    resp = client.post("/students/enrol", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["student_id"] == "21/CY1089"
    assert len(data["trace_id"]) == 32

    # Verify student is in repo
    repo = get_repository()
    student = repo.get_student("21/CY1089")
    assert student is not None
    assert student.name == "Emeka Okonjo"

    # Verify audit trail contains enrollment
    audit = get_audit_log()
    assert any(e.action == "student:enrol" for e in audit.get_entries())


def test_submission_webhook_endpoint(client):
    """POST /webhooks/submission_received stores artifact and advances state machine."""
    repo = get_repository()
    student = Student(
        student_id="21/CY1089",
        name="Emeka Okonjo",
        email="emeka@uniuyo.edu.ng",
        stage=Stage.AWAITING_SUBMISSION,
        room_id="room_01_sqli",
    )
    repo.save_student(student)

    webhook_payload = {
        "submission_id": "sub_1089_01",
        "student_id": "21/CY1089",
        "room_id": "room_01_sqli",
        "artifact": "def patch(query): return db.parameterize(query)",
    }
    resp = client.post("/webhooks/submission_received", json=webhook_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["submission_id"] == "sub_1089_01"
    assert data["stage"] == "SUBMISSION_RECEIVED"

    # Verify submission stored
    sub = repo.get_submission("sub_1089_01")
    assert sub is not None
    assert "parameterize" in sub.artifact


def test_human_approval_webhook_endpoint(client):
    """POST /webhooks/human_approved records instructor decision into audit trail."""
    repo = get_repository()
    student = Student(
        student_id="21/CY1090",
        name="Chidi Uba",
        email="chidi@uniuyo.edu.ng",
        stage=Stage.HUMAN_REVIEW_PENDING,
    )
    repo.save_student(student)

    payload = {
        "student_id": "21/CY1090",
        "instructor_id": "prof_ekong",
        "approved": True,
        "comments": "Approved after manual code verification.",
    }
    resp = client.post("/webhooks/human_approved", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["approved"] is True

    audit = get_audit_log()
    assert any(e.action == "webhook:human_approved" for e in audit.get_entries())


def test_nudge_stalled_task_endpoint(client):
    """POST /tasks/nudge_stalled scans and wakes dormant students."""
    repo = get_repository()
    s1 = Student(student_id="std_dormant", name="Dormant Alice", email="a@test.com", stage=Stage.AWAITING_SUBMISSION)
    s2 = Student(student_id="std_active", name="Active Bob", email="b@test.com", stage=Stage.ASSESSED)
    repo.save_student(s1)
    repo.save_student(s2)

    resp = client.post("/tasks/nudge_stalled", json={"days_idle": 1})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "std_dormant" in data["students"]
    assert "std_active" not in data["students"]


# -----------------------------------------------------------------------------
# 4. Provenance & Money Endpoint
# -----------------------------------------------------------------------------

def test_credential_provenance_money_endpoint(client):
    """GET /credentials/{id}/provenance returns credential, Cloud Trace link, and full student provenance."""
    repo = get_repository()
    audit = get_audit_log()

    student = Student(
        student_id="21/CY9999",
        name="Grace Bassey",
        email="grace@uniuyo.edu.ng",
        stage=Stage.CREDENTIAL_ISSUED,
    )
    repo.save_student(student)

    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    cred = Credential(
        credential_id="cred_9999",
        student_id="21/CY9999",
        cohort_id="cohort_arete_2026",
        badge_name="Arete Certified Cybersecurity Practitioner (ACCP)",
        trace_id=trace_id,
    )
    repo.save_credential(cred)

    # Add audit entries for this student
    audit.record(
        audit_log_entry("registrar", "student:enrol", "21/CY9999", {"room": "room_01"}, trace_id)
    )
    audit.record(
        audit_log_entry("assessor", "assessment:write", "21/CY9999", {"score": 95}, trace_id)
    )
    audit.record(
        audit_log_entry("registrar", "credential:issue", "21/CY9999", {"cred": "cred_9999"}, trace_id)
    )

    resp = client.get("/credentials/cred_9999/provenance")
    assert resp.status_code == 200
    data = resp.json()

    assert data["credential"]["credential_id"] == "cred_9999"
    assert data["student"]["name"] == "Grace Bassey"
    assert trace_id in data["cloud_trace_url"]
    assert data["integrity_check"]["intact"] is True
    assert len(data["provenance_chain"]) == 3
    assert all(entry["verified"] is True for entry in data["provenance_chain"])


def audit_log_entry(actor, action, subject, payload, trace_id):
    """Helper to create a signed ActionEnvelope for testing."""
    from aegis.governance.identity import ActionEnvelope
    return ActionEnvelope(
        actor=actor,
        action=action,
        subject=subject,
        payload=payload,
        trace_id=trace_id,
    ).sign()


# -----------------------------------------------------------------------------
# 5. Dashboard Endpoint
# -----------------------------------------------------------------------------

def test_dashboard_endpoint(client):
    """GET / renders HTML dashboard with status and quick links."""
    repo = get_repository()
    student = Student(student_id="std_dash_1", name="Dash Student", email="dash@test.com", stage=Stage.CREDENTIAL_ISSUED)
    repo.save_student(student)
    cred = Credential(credential_id="cred_dash_1", student_id="std_dash_1", cohort_id="cohort_1", badge_name="ACCP", trace_id="1"*32)
    repo.save_credential(cred)

    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "AEGIS" in resp.text
    assert "Student Cohort Lifecycle Roster" in resp.text
    assert "/credentials/cred_dash_1/provenance" in resp.text
