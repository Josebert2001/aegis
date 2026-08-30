"""Unified repository interface with In-Memory and Firestore backends.

Enforces FSM stage transitions at the data store level before any mutation occurs.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from datetime import datetime, timezone
from dataclasses import asdict

from aegis.config import settings
from aegis.domain import (
    Stage,
    Student,
    Cohort,
    Submission,
    Assessment,
    AdversaryVerdict,
    Credential,
    assert_transition,
    _utcnow_iso,
)


class BaseRepository(ABC):
    """Abstract repository interface for Aegis data models."""

    @abstractmethod
    def save_student(self, student: Student) -> Student:
        pass

    @abstractmethod
    def get_student(self, student_id: str) -> Optional[Student]:
        pass

    @abstractmethod
    def list_students(self) -> List[Student]:
        pass

    @abstractmethod
    def advance(self, student_id: str, target_stage: Stage) -> Student:
        """Transitions a student to a target stage after enforcing FSM rules."""
        pass

    @abstractmethod
    def save_cohort(self, cohort: Cohort) -> Cohort:
        pass

    @abstractmethod
    def get_cohort(self, cohort_id: str) -> Optional[Cohort]:
        pass

    @abstractmethod
    def save_submission(self, submission: Submission) -> Submission:
        pass

    @abstractmethod
    def get_submission(self, submission_id: str) -> Optional[Submission]:
        pass

    @abstractmethod
    def get_latest_submission_for_student(self, student_id: str) -> Optional[Submission]:
        pass

    @abstractmethod
    def save_assessment(self, assessment: Assessment) -> Assessment:
        pass

    @abstractmethod
    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        pass

    @abstractmethod
    def get_latest_assessment_for_student(self, student_id: str) -> Optional[Assessment]:
        pass

    @abstractmethod
    def save_verdict(self, verdict: AdversaryVerdict) -> AdversaryVerdict:
        pass

    @abstractmethod
    def get_verdict(self, verdict_id: str) -> Optional[AdversaryVerdict]:
        pass

    @abstractmethod
    def get_latest_verdict_for_student(self, student_id: str) -> Optional[AdversaryVerdict]:
        pass

    @abstractmethod
    def save_credential(self, credential: Credential) -> Credential:
        pass

    @abstractmethod
    def get_credential(self, credential_id: str) -> Optional[Credential]:
        pass

    @abstractmethod
    def get_credential_by_student(self, student_id: str) -> Optional[Credential]:
        pass


class InMemoryRepository(BaseRepository):
    """In-memory dictionary backed repository for local execution and deterministic tests."""

    def __init__(self) -> None:
        self.students: Dict[str, Student] = {}
        self.cohorts: Dict[str, Cohort] = {}
        self.submissions: Dict[str, Submission] = {}
        self.assessments: Dict[str, Assessment] = {}
        self.verdicts: Dict[str, AdversaryVerdict] = {}
        self.credentials: Dict[str, Credential] = {}

    def save_student(self, student: Student) -> Student:
        student.updated_at = _utcnow_iso()
        self.students[student.student_id] = student
        return student

    def get_student(self, student_id: str) -> Optional[Student]:
        return self.students.get(student_id)

    def list_students(self) -> List[Student]:
        return list(self.students.values())

    def advance(self, student_id: str, target_stage: Stage) -> Student:
        student = self.get_student(student_id)
        if not student:
            raise KeyError(f"Student '{student_id}' not found")
        # Enforce Python FSM guard before mutation
        assert_transition(current=student.stage, target=target_stage)
        student.stage = target_stage
        student.updated_at = _utcnow_iso()
        self.students[student_id] = student
        return student

    def save_cohort(self, cohort: Cohort) -> Cohort:
        self.cohorts[cohort.cohort_id] = cohort
        return cohort

    def get_cohort(self, cohort_id: str) -> Optional[Cohort]:
        return self.cohorts.get(cohort_id)

    def save_submission(self, submission: Submission) -> Submission:
        self.submissions[submission.submission_id] = submission
        return submission

    def get_submission(self, submission_id: str) -> Optional[Submission]:
        return self.submissions.get(submission_id)

    def get_latest_submission_for_student(self, student_id: str) -> Optional[Submission]:
        matching = [s for s in self.submissions.values() if s.student_id == student_id]
        if not matching:
            return None
        return sorted(matching, key=lambda s: s.submitted_at, reverse=True)[0]

    def save_assessment(self, assessment: Assessment) -> Assessment:
        self.assessments[assessment.assessment_id] = assessment
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        return self.assessments.get(assessment_id)

    def get_latest_assessment_for_student(self, student_id: str) -> Optional[Assessment]:
        matching = [a for a in self.assessments.values() if a.student_id == student_id]
        if not matching:
            return None
        return sorted(matching, key=lambda a: a.created_at, reverse=True)[0]

    def save_verdict(self, verdict: AdversaryVerdict) -> AdversaryVerdict:
        self.verdicts[verdict.verdict_id] = verdict
        return verdict

    def get_verdict(self, verdict_id: str) -> Optional[AdversaryVerdict]:
        return self.verdicts.get(verdict_id)

    def get_latest_verdict_for_student(self, student_id: str) -> Optional[AdversaryVerdict]:
        matching = [v for v in self.verdicts.values() if v.student_id == student_id]
        if not matching:
            return None
        return sorted(matching, key=lambda v: v.timestamp, reverse=True)[0]

    def save_credential(self, credential: Credential) -> Credential:
        self.credentials[credential.credential_id] = credential
        return credential

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        return self.credentials.get(credential_id)

    def get_credential_by_student(self, student_id: str) -> Optional[Credential]:
        for cred in self.credentials.values():
            if cred.student_id == student_id:
                return cred
        return None


class FirestoreRepository(BaseRepository):
    """Google Cloud Firestore repository for deployed production instances on Cloud Run."""

    def __init__(self, project_id: Optional[str] = None) -> None:
        from google.cloud import firestore  # Lazy import to keep local startup lightweight
        self.db = firestore.Client(project=project_id or settings.gcp_project)

    def save_student(self, student: Student) -> Student:
        student.updated_at = _utcnow_iso()
        doc_ref = self.db.collection("students").document(student.student_id)
        doc_ref.set({
            "student_id": student.student_id,
            "name": student.name,
            "email": student.email,
            "stage": student.stage.value,
            "room_id": student.room_id,
            "metadata": student.metadata,
            "updated_at": student.updated_at,
        })
        return student

    def get_student(self, student_id: str) -> Optional[Student]:
        doc = self.db.collection("students").document(student_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return Student(
            student_id=data["student_id"],
            name=data["name"],
            email=data["email"],
            stage=Stage(data["stage"]),
            room_id=data.get("room_id"),
            metadata=data.get("metadata", {}),
            updated_at=data.get("updated_at", _utcnow_iso()),
        )

    def list_students(self) -> List[Student]:
        docs = self.db.collection("students").stream()
        res = []
        for doc in docs:
            data = doc.to_dict()
            res.append(
                Student(
                    student_id=data["student_id"],
                    name=data["name"],
                    email=data["email"],
                    stage=Stage(data["stage"]),
                    room_id=data.get("room_id"),
                    metadata=data.get("metadata", {}),
                    updated_at=data.get("updated_at", _utcnow_iso()),
                )
            )
        return res

    def advance(self, student_id: str, target_stage: Stage) -> Student:
        student = self.get_student(student_id)
        if not student:
            raise KeyError(f"Student '{student_id}' not found")
        # Enforce Python FSM guard before mutation
        assert_transition(current=student.stage, target=target_stage)
        student.stage = target_stage
        return self.save_student(student)

    def save_cohort(self, cohort: Cohort) -> Cohort:
        doc_ref = self.db.collection("cohorts").document(cohort.cohort_id)
        doc_ref.set({
            "cohort_id": cohort.cohort_id,
            "name": cohort.name,
            "created_at": cohort.created_at,
        })
        return cohort

    def get_cohort(self, cohort_id: str) -> Optional[Cohort]:
        doc = self.db.collection("cohorts").document(cohort_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return Cohort(
            cohort_id=data["cohort_id"],
            name=data["name"],
            created_at=data.get("created_at", _utcnow_iso()),
        )

    def save_submission(self, submission: Submission) -> Submission:
        doc_ref = self.db.collection("submissions").document(submission.submission_id)
        doc_ref.set({
            "submission_id": submission.submission_id,
            "student_id": submission.student_id,
            "room_id": submission.room_id,
            "artifact": submission.artifact,
            "submitted_at": submission.submitted_at,
            "metadata": submission.metadata,
        })
        return submission

    def get_submission(self, submission_id: str) -> Optional[Submission]:
        doc = self.db.collection("submissions").document(submission_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return Submission(
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            room_id=data["room_id"],
            artifact=data["artifact"],
            submitted_at=data.get("submitted_at", _utcnow_iso()),
            metadata=data.get("metadata", {}),
        )

    def get_latest_submission_for_student(self, student_id: str) -> Optional[Submission]:
        docs = [
            doc.to_dict()
            for doc in self.db.collection("submissions").where("student_id", "==", student_id).stream()
        ]
        if not docs:
            return None
        docs.sort(key=lambda d: d.get("submitted_at", ""), reverse=True)
        data = docs[0]
        return Submission(
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            room_id=data["room_id"],
            artifact=data["artifact"],
            submitted_at=data.get("submitted_at", _utcnow_iso()),
            metadata=data.get("metadata", {}),
        )

    def save_assessment(self, assessment: Assessment) -> Assessment:
        doc_ref = self.db.collection("assessments").document(assessment.assessment_id)
        doc_ref.set({
            "assessment_id": assessment.assessment_id,
            "submission_id": assessment.submission_id,
            "student_id": assessment.student_id,
            "score": assessment.score,
            "passed": assessment.passed,
            "feedback": assessment.feedback,
            "criteria_met": assessment.criteria_met,
            "created_at": assessment.created_at,
        })
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        doc = self.db.collection("assessments").document(assessment_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return Assessment(
            assessment_id=data["assessment_id"],
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            score=data["score"],
            passed=data["passed"],
            feedback=data["feedback"],
            criteria_met=data.get("criteria_met", []),
            created_at=data.get("created_at", _utcnow_iso()),
        )

    def get_latest_assessment_for_student(self, student_id: str) -> Optional[Assessment]:
        docs = [
            doc.to_dict()
            for doc in self.db.collection("assessments").where("student_id", "==", student_id).stream()
        ]
        if not docs:
            return None
        docs.sort(key=lambda d: d.get("created_at", ""), reverse=True)
        data = docs[0]
        return Assessment(
            assessment_id=data["assessment_id"],
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            score=data["score"],
            passed=data["passed"],
            feedback=data["feedback"],
            criteria_met=data.get("criteria_met", []),
            created_at=data.get("created_at", _utcnow_iso()),
        )

    def save_verdict(self, verdict: AdversaryVerdict) -> AdversaryVerdict:
        doc_ref = self.db.collection("verdicts").document(verdict.verdict_id)
        doc_ref.set({
            "verdict_id": verdict.verdict_id,
            "submission_id": verdict.submission_id,
            "student_id": verdict.student_id,
            "exploit_held": verdict.exploit_held,
            "attack_payload": verdict.attack_payload,
            "logs": verdict.logs,
            "timestamp": verdict.timestamp,
        })
        return verdict

    def get_verdict(self, verdict_id: str) -> Optional[AdversaryVerdict]:
        doc = self.db.collection("verdicts").document(verdict_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return AdversaryVerdict(
            verdict_id=data["verdict_id"],
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            exploit_held=data["exploit_held"],
            attack_payload=data["attack_payload"],
            logs=data["logs"],
            timestamp=data.get("timestamp", _utcnow_iso()),
        )

    def get_latest_verdict_for_student(self, student_id: str) -> Optional[AdversaryVerdict]:
        docs = [
            doc.to_dict()
            for doc in self.db.collection("verdicts").where("student_id", "==", student_id).stream()
        ]
        if not docs:
            return None
        docs.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
        data = docs[0]
        return AdversaryVerdict(
            verdict_id=data["verdict_id"],
            submission_id=data["submission_id"],
            student_id=data["student_id"],
            exploit_held=data["exploit_held"],
            attack_payload=data["attack_payload"],
            logs=data["logs"],
            timestamp=data.get("timestamp", _utcnow_iso()),
        )

    def save_credential(self, credential: Credential) -> Credential:
        doc_ref = self.db.collection("credentials").document(credential.credential_id)
        doc_ref.set({
            "credential_id": credential.credential_id,
            "student_id": credential.student_id,
            "cohort_id": credential.cohort_id,
            "badge_name": credential.badge_name,
            "issued_at": credential.issued_at,
            "trace_id": credential.trace_id,
            "metadata": credential.metadata,
        })
        return credential

    def get_credential(self, credential_id: str) -> Optional[Credential]:
        doc = self.db.collection("credentials").document(credential_id).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        return Credential(
            credential_id=data["credential_id"],
            student_id=data["student_id"],
            cohort_id=data["cohort_id"],
            badge_name=data["badge_name"],
            issued_at=data.get("issued_at", _utcnow_iso()),
            trace_id=data["trace_id"],
            metadata=data.get("metadata", {}),
        )

    def get_credential_by_student(self, student_id: str) -> Optional[Credential]:
        docs = [
            doc.to_dict()
            for doc in self.db.collection("credentials").where("student_id", "==", student_id).stream()
        ]
        if not docs:
            return None
        docs.sort(key=lambda d: d.get("issued_at", ""), reverse=True)
        data = docs[0]
        return Credential(
            credential_id=data["credential_id"],
            student_id=data["student_id"],
            cohort_id=data["cohort_id"],
            badge_name=data["badge_name"],
            issued_at=data.get("issued_at", _utcnow_iso()),
            trace_id=data["trace_id"],
            metadata=data.get("metadata", {}),
        )


# Global singleton instance for in-memory repo
_in_memory_instance: Optional[InMemoryRepository] = None


def get_repository() -> BaseRepository:
    """Returns the configured repository backend (Firestore or InMemory)."""
    global _in_memory_instance
    if settings.use_firestore:
        return FirestoreRepository()
    if _in_memory_instance is None:
        _in_memory_instance = InMemoryRepository()
    return _in_memory_instance
