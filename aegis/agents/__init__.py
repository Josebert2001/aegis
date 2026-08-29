"""AEGIS Agents Package.

Contains the governed institutional fleet:
- Registrar Agent (Orchestrator, root_agent)
- Assessor Agent (Security lab grading under untrusted input)
- Adversary Agent (Adversarial stress-testing of patches)
"""

from aegis.agents.tools import (
    advance_student,
    notify_student,
    issue_credential,
    list_stalled_students,
    load_submission,
    record_assessment,
    record_verdict,
)
from aegis.agents.fleet import (
    assessor_agent,
    adversary_agent,
    registrar_agent,
    root_agent,
    initialize_cohort_state,
)

__all__ = [
    "advance_student",
    "notify_student",
    "issue_credential",
    "list_stalled_students",
    "load_submission",
    "record_assessment",
    "record_verdict",
    "assessor_agent",
    "adversary_agent",
    "registrar_agent",
    "root_agent",
    "initialize_cohort_state",
]
