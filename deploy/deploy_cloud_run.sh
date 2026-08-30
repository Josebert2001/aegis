#!/usr/bin/env bash
# ==============================================================================
# AEGIS Cloud Run Deployment Script
# Deploys AEGIS Fleet to Google Cloud Run with:
# - Scale-to-zero (--min-instances 0): Dormant multi-week agents cost $0 when idle.
# - Cost protection (--max-instances 2): Prevents billing runaway from loops.
# - Secret Manager integration for HMAC tamper-evident envelope signatures.
# - Automated Cloud Trace and Firestore Native telemetry bindings.
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || echo '')}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="aegis-fleet"

if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT is not set. Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "======================================================================"
echo "  DEPLOYING AEGIS FORTIFIED ENTERPRISE FLEET TO CLOUD RUN"
echo "  Project:          ${PROJECT_ID}"
echo "  Region:           ${REGION}"
echo "  Service Name:     ${SERVICE_NAME}"
echo "  Scale Policy:     0 to 2 instances (Cost-optimized & Loop-protected)"
echo "======================================================================"
echo

# Deploy container from source directory with Vertex AI configuration (Gemini 3.7 Flash global routing)
ENV_VARS="USE_FIRESTORE=true,EXPORT_TRACES=true,GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_LOCATION=global,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GCP_PROJECT=${PROJECT_ID},GCP_REGION=${REGION},MODEL_REGISTRAR=gemini-3.7-flash,MODEL_ASSESSOR=gemini-3.7-flash,MODEL_ADVERSARY=gemini-3.5-flash-lite,SESSION_DB_URL=sqlite:///./aegis_sessions.db"
if [ -n "${GOOGLE_API_KEY:-}" ]; then
    ENV_VARS="${ENV_VARS},GOOGLE_API_KEY=${GOOGLE_API_KEY}"
fi

gcloud run deploy "${SERVICE_NAME}" \
    --source . \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --platform="managed" \
    --allow-unauthenticated \
    --min-instances=0 \
    --max-instances=2 \
    --memory="1Gi" \
    --cpu="1" \
    --service-account="aegis-registrar@${PROJECT_ID}.iam.gserviceaccount.com" \
    --set-secrets="AEGIS_HMAC_SECRET=aegis-hmac-secret:latest" \
    --set-env-vars="${ENV_VARS}" \
    --quiet

# Retrieve the live deployed URL
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --platform="managed" --region="${REGION}" --project="${PROJECT_ID}" --format="value(status.url)")

echo
echo "======================================================================"
echo "  DEPLOYMENT SUCCESSFUL!"
echo "  Service URL:      ${SERVICE_URL}"
echo "  Health Endpoint:  ${SERVICE_URL}/health"
echo "  Audit Dashboard:  ${SERVICE_URL}/"
echo "======================================================================"
echo
echo ">>> Set up Cloud Scheduler for the Daily Cohort Dormancy Tick:"
echo
echo "gcloud scheduler jobs create http aegis-daily-cohort-nudge \\"
echo "    --schedule=\"0 9 * * *\" \\"
echo "    --uri=\"${SERVICE_URL}/tasks/nudge_stalled\" \\"
echo "    --http-method=POST \\"
echo "    --location=\"${REGION}\" \\"
echo "    --project=\"${PROJECT_ID}\" \\"
echo "    --description=\"Daily 9:00 AM cohort tick to nudge stalled students across multi-week timeline\""
echo
