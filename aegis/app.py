"""AEGIS FastAPI Application and Agent Runtime.

Provides HTTP and webhook interfaces for the multi-week cybersecurity cohort pipeline:
- Student Enrollment
- Asynchronous Submission Webhooks & Dormant Session Wake
- Human Instructor Approval Gates
- Cloud Scheduler Inactivity Nudges
- Cryptographic Provenance & OpenTelemetry Trace Verification
- Dark-Themed Governance Monitoring Dashboard
"""

from dataclasses import asdict
from datetime import datetime, timezone
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Tuple
import uuid

from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from google.genai import types
from google.adk.runners import Runner
from google.adk.sessions import DatabaseSessionService, InMemorySessionService

from aegis.config import settings
from aegis.domain import (
    Stage,
    Student,
    Submission,
    Assessment,
    AdversaryVerdict,
    Credential,
    _utcnow_iso,
)
from aegis.governance.identity import (
    REGISTRAR,
    ASSESSOR,
    ADVERSARY,
    SCOPE_STAGE_ADVANCE,
    SCOPE_CREDENTIAL_ISSUE,
    signed_action,
)
from aegis.governance.audit import get_audit_log
from aegis.governance.registry import get_agent_registry
from aegis.governance.observability import (
    span,
    current_trace_id,
    cloud_trace_url,
    get_tracer,
)
from aegis.store.repository import get_repository
from aegis.agents.fleet import root_agent

logger = logging.getLogger("aegis.app")
logging.basicConfig(level=logging.INFO)

# Initialize OpenTelemetry Tracer
tracer = get_tracer()

# -----------------------------------------------------------------------------
# ADK Session Service & Runner Initialization
# -----------------------------------------------------------------------------

def _create_session_service():
    """Initializes DatabaseSessionService with graceful fallback to InMemorySessionService."""
    db_url = settings.session_db_url
    # Ensure SQLite async driver format is normalized if needed
    if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite+aiosqlite:///"):
        db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///")

    try:
        service = DatabaseSessionService(db_url=db_url)
        logger.info("DatabaseSessionService initialized with URL: %s", db_url)
        return service
    except Exception as exc:
        logger.critical(
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
            "CRITICAL WARNING: DatabaseSessionService failed to initialize (%s).\n"
            "Falling back to InMemorySessionService as a last resort.\n"
            "PAUSE / RESUME ACROSS PROCESS RESTARTS WILL NOT WORK IN PRODUCTION!\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
            exc,
        )
        return InMemorySessionService()


session_service = _create_session_service()
runner = Runner(
    agent=root_agent,
    session_service=session_service,
    app_name="aegis",
)

# Initialize FastAPI App
app = FastAPI(
    title="AEGIS — Institutional Agent Fleet",
    description="Autonomous Cybersecurity Assessment-to-Credential Pipeline with Cryptographic Governance",
    version="1.0.0",
)


# -----------------------------------------------------------------------------
# Agent Wake Helper
# -----------------------------------------------------------------------------

async def _wake(
    student_id: str,
    prompt: str,
    state_delta: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Wakes the long-running Registrar agent for a student's persistent cohort session.

    Derives session_id as 'cohort::{student_id}' so the exact same multi-week
    conversation is resumed every time an event occurs.
    """
    with span("agent.wake", {"student_id": student_id, "prompt_preview": prompt[:80]}):
        trace_id = current_trace_id()
        session_id = f"cohort::{student_id}"

        # 1. Ensure session exists (resume path swallows existing session error)
        try:
            await session_service.create_session(
                app_name="aegis",
                user_id=student_id,
                session_id=session_id,
                state=state_delta or {},
            )
        except Exception as exc:
            logger.debug("Resuming existing session for student %s (%s)", student_id, exc)

        # 2. Construct message Content
        new_message = types.Content(
            role="user",
            parts=[types.Part.from_text(text=prompt)],
        )

        # 3. Asynchronously execute agent with state_delta applied BEFORE inference
        response_texts: List[str] = []
        try:
            async for event in runner.run_async(
                user_id=student_id,
                session_id=session_id,
                new_message=new_message,
                state_delta=state_delta,
            ):
                if hasattr(event, "content") and event.content:
                    for part in getattr(event.content, "parts", []):
                        if getattr(part, "text", None):
                            response_texts.append(part.text)
        except Exception as exc:
            logger.warning("Agent execution note for student %s: %s", student_id, exc)
            return f"Agent processed signal (offline mode/completed): {exc}", trace_id

        final_response = "\n".join(response_texts) if response_texts else "Agent processed cohort signal."
        return final_response, trace_id


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------

class EnrolRequest(BaseModel):
    student_id: str = Field(..., description="Unique student identifier (e.g. 21/CY1089)")
    name: str = Field(..., description="Student full name")
    email: str = Field(..., description="Student institutional email")
    room_id: Optional[str] = Field("room_01_sqli", description="Initial assigned CTF lab room")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict)


class SubmissionWebhookRequest(BaseModel):
    submission_id: str = Field(..., description="Unique submission ID")
    student_id: str = Field(..., description="Student ID who submitted")
    room_id: str = Field(..., description="Challenge room identifier")
    artifact: str = Field(..., description="Untrusted student exploit code / patch")
    metadata: Optional[Dict[str, str]] = Field(default_factory=dict)


class HumanApprovalRequest(BaseModel):
    student_id: str = Field(..., description="Student ID under review")
    instructor_id: str = Field(..., description="Approving instructor / administrator ID")
    approved: bool = Field(..., description="True if approved, False if rejected")
    comments: Optional[str] = Field("", description="Instructor review comments")


class NudgeTaskRequest(BaseModel):
    days_idle: Optional[int] = Field(3, description="Threshold of inactivity in days")


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------

@app.post("/students/enrol", summary="Enrol a student into the cybersecurity cohort")
async def enrol_student(req: EnrolRequest):
    """Creates student profile, records signed audit event, and wakes Registrar to assign room."""
    repo = get_repository()
    audit = get_audit_log()

    student = Student(
        student_id=req.student_id,
        name=req.name,
        email=req.email,
        stage=Stage.ENROLLED,
        room_id=req.room_id,
        metadata=req.metadata or {},
    )
    repo.save_student(student)

    # Cryptographically sign and audit enrollment
    trace_id = current_trace_id()
    env = signed_action(
        identity=REGISTRAR,
        action="student:enrol",
        subject=student.student_id,
        required_scope=SCOPE_STAGE_ADVANCE,
        payload={"name": student.name, "email": student.email, "room_id": student.room_id},
        trace_id=trace_id,
    )
    audit.record(env)

    # Wake Registrar Agent
    prompt = (
        f"New student enrolled: {student.name} (ID: {student.student_id}). "
        f"Advance them to ROOM_ASSIGNED, assign room '{student.room_id}', and then advance to AWAITING_SUBMISSION."
    )
    state_delta = {
        "current_stage": Stage.ENROLLED.value,
        "student_id": student.student_id,
        "student_name": student.name,
        "room_id": student.room_id,
        "pending_signals": ["enrolled"],
    }
    agent_response, wake_trace = await _wake(student.student_id, prompt, state_delta)

    # Re-fetch updated student
    latest = repo.get_student(student.student_id) or student
    return {
        "ok": True,
        "student_id": latest.student_id,
        "stage": latest.stage.value,
        "room_id": latest.room_id,
        "trace_id": wake_trace,
        "agent_response": agent_response,
    }


@app.post("/webhooks/submission_received", summary="Webhook triggered when a student submits lab code")
async def webhook_submission_received(req: SubmissionWebhookRequest):
    """Stores untrusted submission, advances state machine, audits webhook wake, and wakes Registrar."""
    repo = get_repository()
    audit = get_audit_log()

    student = repo.get_student(req.student_id)
    if not student:
        raise HTTPException(status_code=404, detail=f"Student '{req.student_id}' not found")

    # Store submission artifact (holds untrusted attacker text)
    submission = Submission(
        submission_id=req.submission_id,
        student_id=req.student_id,
        room_id=req.room_id,
        artifact=req.artifact,
        metadata=req.metadata or {},
    )
    repo.save_submission(submission)

    # Advance stage to SUBMISSION_RECEIVED if in AWAITING_SUBMISSION
    if student.stage == Stage.AWAITING_SUBMISSION:
        repo.advance(req.student_id, Stage.SUBMISSION_RECEIVED)

    trace_id = current_trace_id()
    # Audit webhook wake event
    env = signed_action(
        identity=REGISTRAR,
        action="webhook:submission_received",
        subject=req.student_id,
        required_scope=SCOPE_STAGE_ADVANCE,
        payload={"submission_id": req.submission_id, "room_id": req.room_id},
        trace_id=trace_id,
    )
    audit.record(env)

    # Wake Registrar with state_delta
    prompt = (
        f"Student {req.student_id} submitted lab artifact for room {req.room_id} "
        f"(Submission ID: {req.submission_id}). Delegate to the assessor agent to evaluate it."
    )
    state_delta = {
        "current_stage": Stage.SUBMISSION_RECEIVED.value,
        "student_id": req.student_id,
        "active_submission_id": req.submission_id,
        "pending_signals": ["submission_received"],
    }
    agent_response, wake_trace = await _wake(req.student_id, prompt, state_delta)

    return {
        "ok": True,
        "submission_id": req.submission_id,
        "student_id": req.student_id,
        "stage": Stage.SUBMISSION_RECEIVED.value,
        "trace_id": wake_trace,
        "agent_response": agent_response,
    }


@app.post("/webhooks/human_approved", summary="Instructor human-in-the-loop review sign-off gate")
async def webhook_human_approved(req: HumanApprovalRequest):
    """Processes instructor sign-off arriving days after human review was requested."""
    repo = get_repository()
    audit = get_audit_log()

    student = repo.get_student(req.student_id)
    if not student:
        raise HTTPException(status_code=404, detail=f"Student '{req.student_id}' not found")

    trace_id = current_trace_id()
    env = signed_action(
        identity=REGISTRAR,
        action="webhook:human_approved",
        subject=req.student_id,
        required_scope=SCOPE_STAGE_ADVANCE,
        payload={
            "instructor_id": req.instructor_id,
            "approved": req.approved,
            "comments": req.comments,
        },
        trace_id=trace_id,
    )
    audit.record(env)

    if req.approved:
        prompt = (
            f"Instructor {req.instructor_id} has APPROVED the human review for student {req.student_id}. "
            f"Comments: '{req.comments}'. Proceed to issue credential."
        )
    else:
        prompt = (
            f"Instructor {req.instructor_id} has REJECTED the submission for student {req.student_id}. "
            f"Comments: '{req.comments}'. Transition student to FAILED_NEEDS_RESUBMIT and notify them."
        )

    state_delta = {
        "human_review_approved": req.approved,
        "instructor_comments": req.comments,
        "pending_signals": ["human_review_resolved"],
    }
    agent_response, wake_trace = await _wake(req.student_id, prompt, state_delta)

    return {
        "ok": True,
        "student_id": req.student_id,
        "approved": req.approved,
        "trace_id": wake_trace,
        "agent_response": agent_response,
    }


@app.post("/tasks/nudge_stalled", summary="Cloud Scheduler task to wake dormant students")
async def nudge_stalled_students(req: Optional[NudgeTaskRequest] = None):
    """Cloud Scheduler hits this endpoint to wake students dormant in AWAITING_SUBMISSION."""
    repo = get_repository()
    days_idle = req.days_idle if req else 3
    students = repo.list_students()

    nudged: List[str] = []
    for s in students:
        if s.stage == Stage.AWAITING_SUBMISSION:
            prompt = (
                f"Student {s.name} ({s.student_id}) has been awaiting submission in room '{s.room_id}'. "
                f"Send a reminder notification encouraging them to submit their exploit patch."
            )
            state_delta = {
                "current_stage": s.stage.value,
                "student_id": s.student_id,
                "pending_signals": ["nudge_reminder"],
            }
            await _wake(s.student_id, prompt, state_delta)
            nudged.append(s.student_id)

    return {
        "ok": True,
        "nudged_count": len(nudged),
        "students": nudged,
    }


@app.get("/health", summary="Health check and runtime configuration")
async def health_check():
    """Returns health status, active models, and cloud configuration booleans."""
    return {
        "status": "healthy",
        "service": "aegis-fleet",
        "gcp_project": settings.gcp_project,
        "gcp_region": settings.gcp_region,
        "models": {
            "registrar": settings.model_registrar,
            "assessor": settings.model_assessor,
            "adversary": settings.model_adversary,
        },
        "cloud_flags": {
            "use_firestore": settings.use_firestore,
            "export_traces": settings.export_traces,
            "use_model_armor": settings.use_model_armor,
        },
        "session_db_url": settings.session_db_url,
    }


@app.get("/registry", summary="Agent Registry and Governed Discovery")
async def query_registry(
    capability: Optional[str] = Query(None, description="Capability to filter by"),
    department: Optional[str] = Query(None, description="Requesting department for clearance"),
):
    """Discovers available institutional agents with departmental access control."""
    registry = get_agent_registry()
    if capability and department:
        manifests = registry.discover(capability=capability, department=department)
    else:
        manifests = registry.list_all()

    return {
        "count": len(manifests),
        "agents": [
            {
                "agent_id": m.agent_id,
                "version": m.version,
                "description": m.description,
                "capabilities": m.capabilities,
                "scopes": sorted(list(m.scopes)),
                "service_account": m.service_account,
                "model": m.model,
                "owner_department": m.owner_department,
                "shared_with": m.shared_with,
                "status": m.status,
            }
            for m in manifests
        ],
    }


@app.get("/audit", summary="Append-only cryptographic audit trail and chain verification")
async def get_audit_trail():
    """Returns complete immutable event log and HMAC-SHA256 signature chain verification."""
    audit = get_audit_log()
    events = audit.get_entries()
    integrity = audit.verify_chain()

    return {
        "integrity": integrity,
        "total_events": len(events),
        "events": [
            {
                "actor": e.actor,
                "action": e.action,
                "subject": e.subject,
                "payload": e.payload,
                "timestamp": e.timestamp,
                "trace_id": e.trace_id,
                "signature": e.signature,
                "verified": e.verify(),
            }
            for e in events
        ],
    }


@app.get("/credentials/{credential_id}/provenance", summary="Accreditation and employer provenance inspection")
async def get_credential_provenance(credential_id: str):
    """The Money Endpoint: Returns verifiable credential, Cloud Trace deep link, integrity check, and student audit provenance."""
    repo = get_repository()
    audit = get_audit_log()

    cred = repo.get_credential(credential_id)
    if not cred:
        raise HTTPException(status_code=404, detail=f"Credential '{credential_id}' not found")

    student = repo.get_student(cred.student_id)
    student_events = audit.for_subject(cred.student_id)
    trace_url = cloud_trace_url(cred.trace_id)
    integrity = audit.verify_chain()

    return {
        "credential": asdict(cred),
        "student": asdict(student) if student else None,
        "cloud_trace_url": trace_url,
        "integrity_check": integrity,
        "provenance_chain": [
            {
                "actor": e.actor,
                "action": e.action,
                "subject": e.subject,
                "payload": e.payload,
                "timestamp": e.timestamp,
                "trace_id": e.trace_id,
                "signature": e.signature,
                "verified": e.verify(),
            }
            for e in student_events
        ],
    }


# -----------------------------------------------------------------------------
# Dark-Themed Governance Monitoring Dashboard
# -----------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse, summary="AEGIS Fleet Dashboard")
async def dashboard():
    """Renders a sleek dark-themed status dashboard for monitoring student cohorts and audit integrity."""
    repo = get_repository()
    audit = get_audit_log()

    students = repo.list_students()
    events = audit.get_entries()
    integrity = audit.verify_chain()

    # Count credentials
    credentials_issued = sum(1 for s in students if s.stage == Stage.CREDENTIAL_ISSUED)

    # Build student rows
    rows_html = ""
    for s in students:
        stage_color = {
            "ENROLLED": "#94a3b8",
            "ROOM_ASSIGNED": "#60a5fa",
            "AWAITING_SUBMISSION": "#fbbf24",
            "SUBMISSION_RECEIVED": "#38bdf8",
            "ASSESSED": "#a78bfa",
            "ADVERSARY_VERIFIED": "#34d399",
            "HUMAN_REVIEW_PENDING": "#f43f5e",
            "CREDENTIAL_ISSUED": "#10b981",
            "FAILED_NEEDS_RESUBMIT": "#ef4444",
            "WITHDRAWN": "#64748b",
        }.get(s.stage.value, "#94a3b8")

        cred = repo.get_credential_by_student(s.student_id)
        prov_link = (
            f'<a href="/credentials/{cred.credential_id}/provenance" class="btn-link" target="_blank">View Provenance</a>'
            if cred
            else '<span class="text-muted">In Progress</span>'
        )

        rows_html += f"""
        <tr>
            <td class="mono font-bold">{s.student_id}</td>
            <td>{s.name}</td>
            <td class="text-muted">{s.email}</td>
            <td><code>{s.room_id or 'none'}</code></td>
            <td>
                <span class="badge" style="background: {stage_color}22; color: {stage_color}; border: 1px solid {stage_color}55;">
                    {s.stage.value}
                </span>
            </td>
            <td class="mono text-muted text-sm">{s.updated_at[:19]}</td>
            <td>{prov_link}</td>
        </tr>
        """

    if not rows_html:
        rows_html = '<tr><td colspan="7" class="text-center text-muted py-4">No students currently enrolled. Use <code>POST /students/enrol</code> to start a cohort.</td></tr>'

    integrity_badge = (
        '<span class="badge badge-success">INTACT (100% Tamper-Evident)</span>'
        if integrity.get("intact")
        else '<span class="badge badge-danger">TAMPER DETECTED</span>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS // Autonomous Institutional Agent Fleet</title>
    <style>
        :root {{
            --bg: #090d16;
            --card-bg: #111827;
            --border: #1f2937;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --danger: #ef4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }}
        .logo {{ font-size: 1.5rem; font-weight: 800; letter-spacing: 0.05em; color: #fff; display: flex; align-items: center; gap: 0.5rem; }}
        .logo span {{ color: var(--accent); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.25rem; margin-bottom: 2rem; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
        }}
        .card h3 {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }}
        .card .stat {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
        .table-container {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 2rem;
        }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #1f293788; padding: 1rem; font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }}
        td {{ padding: 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
        tr:last-child td {{ border-bottom: none; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .font-bold {{ font-weight: 600; }}
        .text-muted {{ color: var(--text-muted); }}
        .text-sm {{ font-size: 0.8rem; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.02em;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .btn-link {{ color: var(--accent); text-decoration: none; font-weight: 500; }}
        .btn-link:hover {{ text-decoration: underline; }}
        .quick-links {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; }}
        .quick-links a {{
            padding: 0.5rem 1rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            text-decoration: none;
            font-size: 0.85rem;
            transition: all 0.15s ease;
        }}
        .quick-links a:hover {{ border-color: var(--accent); color: var(--accent); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                AEGIS <span>//</span> FLEET GOVERNANCE
            </div>
            <div>
                {integrity_badge}
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <h3>Total Cohort Students</h3>
                <div class="stat">{len(students)}</div>
            </div>
            <div class="card">
                <h3>Credentials Issued</h3>
                <div class="stat" style="color: var(--success);">{credentials_issued}</div>
            </div>
            <div class="card">
                <h3>Audit Trail Events</h3>
                <div class="stat">{len(events)}</div>
            </div>
            <div class="card">
                <h3>Active Deployment</h3>
                <div class="stat" style="font-size: 1.2rem; color: var(--accent);">{settings.gcp_region}</div>
            </div>
        </div>

        <h2 style="font-size: 1.1rem; margin-bottom: 1rem; color: #fff;">Student Cohort Lifecycle Roster</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Student ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Room ID</th>
                        <th>Lifecycle Stage</th>
                        <th>Last Checkpoint</th>
                        <th>Verification</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>

        <h2 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: #fff;">Institutional Governance Links</h2>
        <div class="quick-links">
            <a href="/docs" target="_blank">Interactive API Docs (/docs)</a>
            <a href="/registry" target="_blank">Agent Registry (/registry)</a>
            <a href="/audit" target="_blank">Cryptographic Audit Trail (/audit)</a>
            <a href="/health" target="_blank">Health & Models (/health)</a>
        </div>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html)


# -----------------------------------------------------------------------------
# Standalone Local Entrypoint
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)
