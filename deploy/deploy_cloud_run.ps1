# ==============================================================================
# AEGIS Cloud Run Deployment Script (PowerShell / Windows)
# ==============================================================================
param(
    [string]$ProjectId = $env:GCP_PROJECT,
    [string]$Region = $(if ($env:GCP_REGION) { $env:GCP_REGION } else { "us-central1" }),
    [string]$ServiceName = "aegis-fleet"
)

if (-not $ProjectId) {
    Write-Error "GCP_PROJECT environment variable or -ProjectId parameter is required."
    exit 1
}

Write-Host "======================================================================"
Write-Host "  DEPLOYING AEGIS FLEET TO CLOUD RUN (PowerShell)"
Write-Host "  Project:      $ProjectId"
Write-Host "  Region:       $Region"
Write-Host "  Service Name: $ServiceName"
Write-Host "  Scale Policy: 0 to 2 instances (Dormancy = \$0 idle cost)"
Write-Host "======================================================================"

gcloud run deploy $ServiceName `
    --source . `
    --region=$Region `
    --project=$ProjectId `
    --platform="managed" `
    --allow-unauthenticated `
    --min-instances=0 `
    --max-instances=2 `
    --memory="1Gi" `
    --cpu="1" `
    --service-account="aegis-registrar@$ProjectId.iam.gserviceaccount.com" `
    --set-secrets="AEGIS_HMAC_SECRET=aegis-hmac-secret:latest" `
    --set-env-vars="USE_FIRESTORE=true,EXPORT_TRACES=true,GCP_PROJECT=$ProjectId,GCP_REGION=$Region,MODEL_REGISTRAR=gemini-3.7-flash,MODEL_ASSESSOR=gemini-3.7-flash,MODEL_ADVERSARY=gemini-3.5-flash-lite,SESSION_DB_URL=sqlite:///./aegis_sessions.db" `
    --quiet

$serviceUrl = gcloud run services describe $ServiceName --platform="managed" --region=$Region --project=$ProjectId --format="value(status.url)"

Write-Host "`n======================================================================"
Write-Host "  DEPLOYMENT SUCCESSFUL!"
Write-Host "  Service URL:      $serviceUrl"
Write-Host "  Health Endpoint:  $serviceUrl/health"
Write-Host "  Audit Dashboard:  $serviceUrl/"
Write-Host "======================================================================"

Write-Host "`n>>> Set up Cloud Scheduler for the Daily Cohort Dormancy Tick:"
Write-Host "gcloud scheduler jobs create http aegis-daily-cohort-nudge --schedule=`"0 9 * * *`" --uri=`"$serviceUrl/tasks/nudge_stalled`" --http-method=POST --location=`"$Region`" --project=`"$ProjectId`" --description=`"Daily 9:00 AM cohort tick to nudge stalled students across multi-week timeline`""
