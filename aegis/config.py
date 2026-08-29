"""Configuration module for Aegis.

Provides environment-driven settings so the exact same codebase runs in local
development (zero-cloud dependencies with SQLite, in-memory repository, and local
screening fallbacks) and on Google Cloud Run (Firestore, Cloud Trace, Secret Manager,
Model Armor).
"""

import os
from dataclasses import dataclass
from typing import Optional
from dotenv import load_dotenv

# Load local environment variables if present
load_dotenv()


def _get_bool_env(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    """Aegis runtime settings."""

    # Google Cloud Project Configuration
    gcp_project: str = os.getenv("GCP_PROJECT", "aegis-fleet-local")
    gcp_region: str = os.getenv("GCP_REGION", "us-central1")

    # Model IDs (Hard rule: Gemini 3.5+; never set temperature/top_p/top_k)
    model_registrar: str = os.getenv("MODEL_REGISTRAR", "gemini-3.7-flash")
    model_assessor: str = os.getenv("MODEL_ASSESSOR", "gemini-3.7-flash")
    model_adversary: str = os.getenv("MODEL_ADVERSARY", "gemini-3.5-flash-lite")

    # ADK Session Persistence
    session_db_url: str = os.getenv("SESSION_DB_URL", "sqlite:///./aegis_sessions.db")

    # Cloud Service Flags & Fallbacks
    use_firestore: bool = _get_bool_env("USE_FIRESTORE", False)
    export_traces: bool = _get_bool_env("EXPORT_TRACES", False)
    use_model_armor: bool = _get_bool_env("USE_MODEL_ARMOR", False)

    # Security & Governance
    # Secret Manager secret name: aegis-hmac-secret -> Mounted as AEGIS_HMAC_SECRET
    hmac_secret_key: str = os.getenv(
        "AEGIS_HMAC_SECRET",
        os.getenv("AEGIS_SIGNING_KEY", "local-ephemeral-secret-key-32b-min"),
    )

    # API & Service Configuration
    port: int = int(os.getenv("PORT", "8080"))
    host: str = os.getenv("HOST", "0.0.0.0")


# Global singleton settings instance
settings = Settings()
