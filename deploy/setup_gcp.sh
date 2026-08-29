#!/usr/bin/env bash
# ==============================================================================
# AEGIS GCP Setup Script (Idempotent)
# Sets up GCP APIs, Firestore Native database, least-privilege agent service
# accounts, and Secret Manager HMAC signing secret.
# ==============================================================================
set -euo pipefail

PROJECT_ID="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null || echo '')}"
REGION="${GCP_REGION:-us-central1}"

if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT is not set. Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "======================================================================"
echo "  AEGIS FLEET GCP INFRASTRUCTURE SETUP"
echo "  Project: ${PROJECT_ID}"
echo "  Region:  ${REGION}"
echo "======================================================================"
echo

# 1. Enable Required GCP APIs
echo ">>> [1/4] Enabling required Google Cloud APIs..."
APIS=(
    "aiplatform.googleapis.com"
    "run.googleapis.com"
    "firestore.googleapis.com"
    "pubsub.googleapis.com"
    "cloudscheduler.googleapis.com"
    "secretmanager.googleapis.com"
    "cloudtrace.googleapis.com"
    "artifactregistry.googleapis.com"
    "cloudbuild.googleapis.com"
)

for api in "${APIS[@]}"; do
    echo "  - Enabling ${api}..."
    gcloud services enable "$api" --project="${PROJECT_ID}" --quiet || true
done
echo "[OK] APIs enabled."
echo

# 2. Create Firestore Native Database (if not existing)
echo ">>> [2/4] Initializing Firestore Native Database..."
if ! gcloud firestore databases describe --project="${PROJECT_ID}" --format="value(name)" >/dev/null 2>&1; then
    echo "  - Creating Firestore default database in ${REGION}..."
    gcloud firestore databases create --location="${REGION}" --type=firestore-native --project="${PROJECT_ID}" --quiet || true
else
    echo "  - Firestore database already exists."
fi
echo "[OK] Firestore initialized."
echo

# 3. Create Three Dedicated Agent Service Accounts (Least Privilege)
echo ">>> [3/4] Creating Agent Identity Service Accounts..."

create_sa_if_missing() {
    local SA_NAME="$1"
    local DISPLAY_NAME="$2"
    local SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

    if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo "  - Creating service account: ${SA_NAME}..."
        gcloud iam service-accounts create "${SA_NAME}" \
            --display-name="${DISPLAY_NAME}" \
            --project="${PROJECT_ID}" --quiet
    else
        echo "  - Service account ${SA_NAME} already exists."
    fi
}

create_sa_if_missing "aegis-registrar" "AEGIS Registrar Orchestrator Agent"
create_sa_if_missing "aegis-assessor"  "AEGIS Lab Assessor Agent (Least Privilege)"
create_sa_if_missing "aegis-adversary" "AEGIS Adversary Verification Agent"

echo "  - Binding least-privilege IAM roles..."
# Registrar: Full lifecycle orchestration, Firestore read/write, Trace export, Vertex invocation
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-registrar@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user" --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-registrar@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/datastore.user" --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-registrar@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/cloudtrace.agent" --condition=None --quiet >/dev/null

# Assessor: Strictly text assessment under untrusted boundaries; no credential issuance permissions
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-assessor@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user" --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-assessor@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/datastore.viewer" --condition=None --quiet >/dev/null

# Adversary: Security attack simulation; no credential issuance permissions
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-adversary@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user" --condition=None --quiet >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:aegis-adversary@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/datastore.viewer" --condition=None --quiet >/dev/null

echo "[OK] Service accounts configured with strict least-privilege boundaries."
echo

# 4. Generate Secret Manager HMAC Envelope Signing Secret
echo ">>> [4/4] Configuring Secret Manager HMAC Secret..."
SECRET_NAME="aegis-hmac-secret"

if ! gcloud secrets describe "${SECRET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo "  - Creating secret: ${SECRET_NAME}..."
    gcloud secrets create "${SECRET_NAME}" --replication-policy="automatic" --project="${PROJECT_ID}" --quiet
    
    # Generate 32-byte hex key
    NEW_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    echo -n "${NEW_KEY}" | gcloud secrets versions add "${SECRET_NAME}" --data-file=- --project="${PROJECT_ID}" --quiet
    echo "  - Stored initial cryptographic signing key."
else
    echo "  - Secret ${SECRET_NAME} already exists."
fi

# Allow Registrar SA to access the secret
gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
    --member="serviceAccount:aegis-registrar@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" --quiet >/dev/null

echo "[OK] Secret Manager setup complete."
echo
echo "======================================================================"
echo "  GCP SETUP COMPLETE! Run ./deploy/deploy_cloud_run.sh to deploy."
echo "======================================================================"
