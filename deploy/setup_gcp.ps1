# ==============================================================================
# AEGIS GCP Setup Script (PowerShell / Windows)
# ==============================================================================
param(
    [string]$ProjectId = $env:GCP_PROJECT,
    [string]$Region = $(if ($env:GCP_REGION) { $env:GCP_REGION } else { "us-central1" })
)

if (-not $ProjectId) {
    Write-Error "GCP_PROJECT environment variable or -ProjectId parameter is required."
    exit 1
}

Write-Host "======================================================================"
Write-Host "  AEGIS FLEET GCP INFRASTRUCTURE SETUP (PowerShell)"
Write-Host "  Project: $ProjectId"
Write-Host "  Region:  $Region"
Write-Host "======================================================================"

# 1. Enable Required GCP APIs
$apis = @(
    "aiplatform.googleapis.com",
    "run.googleapis.com",
    "firestore.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudtrace.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com"
)

Write-Host "`n>>> [1/4] Enabling required Google Cloud APIs..."
foreach ($api in $apis) {
    Write-Host "  - Enabling $api..."
    gcloud services enable $api --project=$ProjectId --quiet
}

# 2. Initialize Firestore Native Database
Write-Host "`n>>> [2/4] Initializing Firestore Native Database..."
gcloud firestore databases create --location=$Region --type=firestore-native --project=$ProjectId --quiet 2>$null

# 3. Create Three Agent Service Accounts
Write-Host "`n>>> [3/4] Creating Agent Identity Service Accounts..."
$sas = @(
    @{ Name="aegis-registrar"; Display="AEGIS Registrar Orchestrator Agent" },
    @{ Name="aegis-assessor";  Display="AEGIS Lab Assessor Agent (Least Privilege)" },
    @{ Name="aegis-adversary"; Display="AEGIS Adversary Verification Agent" }
)

foreach ($sa in $sas) {
    Write-Host "  - Configuring $($sa.Name)..."
    gcloud iam service-accounts create $sa.Name --display-name=$sa.Display --project=$ProjectId --quiet 2>$null
}

# Bind IAM roles
gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-registrar@$ProjectId.iam.gserviceaccount.com" --role="roles/aiplatform.user" --quiet
gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-registrar@$ProjectId.iam.gserviceaccount.com" --role="roles/datastore.user" --quiet
gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-registrar@$ProjectId.iam.gserviceaccount.com" --role="roles/cloudtrace.agent" --quiet

gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-assessor@$ProjectId.iam.gserviceaccount.com" --role="roles/aiplatform.user" --quiet
gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-assessor@$ProjectId.iam.gserviceaccount.com" --role="roles/datastore.viewer" --quiet

gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-adversary@$ProjectId.iam.gserviceaccount.com" --role="roles/aiplatform.user" --quiet
gcloud projects add-iam-policy-binding $ProjectId --member="serviceAccount:aegis-adversary@$ProjectId.iam.gserviceaccount.com" --role="roles/datastore.viewer" --quiet

# 4. Secret Manager HMAC Key
Write-Host "`n>>> [4/4] Configuring Secret Manager HMAC Secret..."
$secretName = "aegis-hmac-secret"
gcloud secrets create $secretName --replication-policy="automatic" --project=$ProjectId --quiet 2>$null

$newKey = python -c "import secrets; print(secrets.token_hex(32))"
$newKey | gcloud secrets versions add $secretName --data-file=- --project=$ProjectId --quiet 2>$null

gcloud secrets add-iam-policy-binding $secretName --member="serviceAccount:aegis-registrar@$ProjectId.iam.gserviceaccount.com" --role="roles/secretmanager.secretAccessor" --project=$ProjectId --quiet

Write-Host "`n[OK] GCP Setup Complete!"
