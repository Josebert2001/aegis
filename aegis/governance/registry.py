"""Institutional Agent Registry and Cross-Department Discovery.

Architectural Rules:
1. FORMAL CAPABILITY AND SCOPE MANIFESTS. Agents publish declarative manifests
   specifying their version, owner department, service account, models, and scopes.
2. GOVERNED CROSS-DEPARTMENT REUSE. Discovery is gated: an agent is only discoverable
   if the requesting department is the owner or explicitly listed in shared_with.
"""

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional

from aegis.config import settings
from aegis.governance.identity import (
    REGISTRAR,
    ASSESSOR,
    ADVERSARY,
    SCOPE_SUBMISSION_READ,
    SCOPE_ASSESSMENT_WRITE,
    SCOPE_ADVERSARY_RUN,
    SCOPE_STAGE_ADVANCE,
    SCOPE_CREDENTIAL_ISSUE,
    SCOPE_STUDENT_NOTIFY,
)


@dataclass
class AgentManifest:
    """Institutional metadata, governance clearance, and capability manifest for an agent."""

    agent_id: str
    version: str
    description: str
    capabilities: List[str]
    scopes: FrozenSet[str]
    service_account: str
    model: str
    owner_department: str
    shared_with: List[str] = field(default_factory=list)
    status: str = "ACTIVE"


class AgentRegistry:
    """Central registry providing publication, governed discovery, and resolution of institutional agents."""

    def __init__(self) -> None:
        self._manifests: Dict[str, AgentManifest] = {}

    def publish(self, manifest: AgentManifest) -> AgentManifest:
        """Publishes or updates an agent manifest in the registry."""
        self._manifests[manifest.agent_id] = manifest
        return manifest

    def resolve(self, agent_id: str) -> Optional[AgentManifest]:
        """Resolves an agent manifest by unique agent_id."""
        return self._manifests.get(agent_id)

    def list_all(self) -> List[AgentManifest]:
        """Returns all registered agent manifests."""
        return list(self._manifests.values())

    def discover(self, capability: str, department: str) -> List[AgentManifest]:
        """Discovers agents providing a capability that the requesting department is cleared to access.

        Access is granted if:
        1. The manifest includes the requested capability.
        2. The requesting department is the owner, or is in shared_with, or shared_with contains "*".
        """
        matching: List[AgentManifest] = []
        for manifest in self._manifests.values():
            # Check capability
            if capability not in manifest.capabilities:
                continue

            # Check departmental clearance
            is_owner = manifest.owner_department == department
            is_shared = department in manifest.shared_with or "*" in manifest.shared_with

            if is_owner or is_shared:
                matching.append(manifest)

        return matching


def bootstrap_registry() -> AgentRegistry:
    """Initializes and returns a registry populated with the three AEGIS institutional agents.

    Demonstrates cross-departmental reuse by sharing the Assessor agent with 'UniUyo Data Science'.
    """
    registry = AgentRegistry()

    # 1. Registrar Agent
    registry.publish(
        AgentManifest(
            agent_id=REGISTRAR.agent_id,
            version=REGISTRAR.version,
            description="Autonomous student enrollment, cohort stage advancement, and verifiable credential issuance.",
            capabilities=[
                "student_enrollment",
                "stage_advancement",
                "credential_issuance",
                "student_notification",
            ],
            scopes=REGISTRAR.scopes,
            service_account=REGISTRAR.service_account,
            model=settings.model_registrar,
            owner_department="Cybersecurity Department",
            shared_with=[],
            status="ACTIVE",
        )
    )

    # 2. Assessor Agent (Shared with UniUyo Data Science for cross-department reuse demo)
    registry.publish(
        AgentManifest(
            agent_id=ASSESSOR.agent_id,
            version=ASSESSOR.version,
            description="Automated security lab grading, exploit patch analysis, and rubric evaluation under untrusted student inputs.",
            capabilities=[
                "security_lab_assessment",
                "rubric_evaluation",
                "patch_analysis",
            ],
            scopes=ASSESSOR.scopes,
            service_account=ASSESSOR.service_account,
            model=settings.model_assessor,
            owner_department="Cybersecurity Department",
            shared_with=["UniUyo Data Science"],  # Cross-department reuse demo beat
            status="ACTIVE",
        )
    )

    # 3. Adversary Agent
    registry.publish(
        AgentManifest(
            agent_id=ADVERSARY.agent_id,
            version=ADVERSARY.version,
            description="Adversarial stress-testing agent that launches targeted exploit payloads against student security patches.",
            capabilities=[
                "adversarial_verification",
                "exploit_simulation",
                "patch_stress_testing",
            ],
            scopes=ADVERSARY.scopes,
            service_account=ADVERSARY.service_account,
            model=settings.model_adversary,
            owner_department="Cybersecurity Department",
            shared_with=[],
            status="ACTIVE",
        )
    )

    return registry


# Singleton registry instance
_registry_instance: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    """Returns the singleton AgentRegistry instance, bootstrapping it if necessary."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = bootstrap_registry()
    return _registry_instance
