#!/bin/sh
set -eu

# Pulpo independent-authority bootstrap helper.
#
# Default behavior is plan-only. Set PULPO_APPLY=1 only when the operator has
# independently selected and authorized the exact Google Cloud project and
# resources. This script never locks a retention policy; bucket locking is an
# irreversible ceremony and must remain a separate explicit action.

: "${PULPO_GCP_PROJECT_ID:?set PULPO_GCP_PROJECT_ID}"
: "${PULPO_GCP_REGION:?set PULPO_GCP_REGION}"
: "${PULPO_AUTHORITY_SA_NAME:=pulpo-authority}"
: "${PULPO_WORKER_SA_NAME:=pulpo-governed-worker}"
: "${PULPO_KMS_KEYRING:=pulpo-authority}"
: "${PULPO_KMS_KEY:=approval-signer}"
: "${PULPO_EVIDENCE_BUCKET:?set globally unique PULPO_EVIDENCE_BUCKET}"
: "${PULPO_EVIDENCE_RETENTION:=P30D}"
: "${PULPO_APPLY:=0}"

AUTHORITY_SA="${PULPO_AUTHORITY_SA_NAME}@${PULPO_GCP_PROJECT_ID}.iam.gserviceaccount.com"
WORKER_SA="${PULPO_WORKER_SA_NAME}@${PULPO_GCP_PROJECT_ID}.iam.gserviceaccount.com"
KEY_VERSION="projects/${PULPO_GCP_PROJECT_ID}/locations/${PULPO_GCP_REGION}/keyRings/${PULPO_KMS_KEYRING}/cryptoKeys/${PULPO_KMS_KEY}/cryptoKeyVersions/1"
AUTHORITY_ORIGIN="https://authority.pulpo.ai"

run() {
  printf '+ %s\n' "$*"
  if [ "$PULPO_APPLY" = "1" ]; then
    "$@"
  fi
}

printf '%s\n' "Pulpo GCP authority bootstrap"
printf '%s\n' "project=${PULPO_GCP_PROJECT_ID}"
printf '%s\n' "region=${PULPO_GCP_REGION}"
printf '%s\n' "authority_service_account=${AUTHORITY_SA}"
printf '%s\n' "worker_service_account=${WORKER_SA}"
printf '%s\n' "kms_key_version=${KEY_VERSION}"
printf '%s\n' "evidence_bucket=gs://${PULPO_EVIDENCE_BUCKET}"
printf '%s\n' "authority_origin=${AUTHORITY_ORIGIN}"
printf '%s\n' "apply=${PULPO_APPLY}"

run gcloud config set project "$PULPO_GCP_PROJECT_ID"
run gcloud services enable run.googleapis.com cloudkms.googleapis.com storage.googleapis.com iamcredentials.googleapis.com sqladmin.googleapis.com artifactregistry.googleapis.com

if [ "$PULPO_APPLY" = "1" ]; then
  gcloud iam service-accounts describe "$AUTHORITY_SA" >/dev/null 2>&1 || \
    run gcloud iam service-accounts create "$PULPO_AUTHORITY_SA_NAME" --display-name="Pulpo independent authority service"
  gcloud iam service-accounts describe "$WORKER_SA" >/dev/null 2>&1 || \
    run gcloud iam service-accounts create "$PULPO_WORKER_SA_NAME" --display-name="Pulpo governed worker"
else
  printf '%s\n' "+ ensure service account ${AUTHORITY_SA}"
  printf '%s\n' "+ ensure service account ${WORKER_SA}"
fi

if [ "$PULPO_APPLY" = "1" ]; then
  gcloud kms keyrings describe "$PULPO_KMS_KEYRING" --location="$PULPO_GCP_REGION" >/dev/null 2>&1 || \
    run gcloud kms keyrings create "$PULPO_KMS_KEYRING" --location="$PULPO_GCP_REGION"
  gcloud kms keys describe "$PULPO_KMS_KEY" --keyring="$PULPO_KMS_KEYRING" --location="$PULPO_GCP_REGION" >/dev/null 2>&1 || \
    run gcloud kms keys create "$PULPO_KMS_KEY" \
      --keyring="$PULPO_KMS_KEYRING" \
      --location="$PULPO_GCP_REGION" \
      --purpose=asymmetric-signing \
      --default-algorithm=ec-sign-p256-sha256 \
      --protection-level=hsm
else
  printf '%s\n' "+ ensure HSM EC_SIGN_P256_SHA256 key ${PULPO_KMS_KEYRING}/${PULPO_KMS_KEY}"
fi

run gcloud kms keys add-iam-policy-binding "$PULPO_KMS_KEY" \
  --keyring="$PULPO_KMS_KEYRING" \
  --location="$PULPO_GCP_REGION" \
  --member="serviceAccount:${AUTHORITY_SA}" \
  --role=roles/cloudkms.signerVerifier

if [ "$PULPO_APPLY" = "1" ]; then
  gcloud storage buckets describe "gs://${PULPO_EVIDENCE_BUCKET}" >/dev/null 2>&1 || \
    run gcloud storage buckets create "gs://${PULPO_EVIDENCE_BUCKET}" \
      --project="$PULPO_GCP_PROJECT_ID" \
      --location="$PULPO_GCP_REGION" \
      --uniform-bucket-level-access
else
  printf '%s\n' "+ ensure evidence bucket gs://${PULPO_EVIDENCE_BUCKET}"
fi

run gcloud storage buckets update "gs://${PULPO_EVIDENCE_BUCKET}" --retention-period="$PULPO_EVIDENCE_RETENTION"
run gcloud storage buckets add-iam-policy-binding "gs://${PULPO_EVIDENCE_BUCKET}" \
  --member="serviceAccount:${AUTHORITY_SA}" \
  --role=roles/storage.objectCreator

printf '%s\n' ""
printf '%s\n' "STOP: retention policy is intentionally NOT locked by this script."
printf '%s\n' "Bucket Lock is irreversible and requires a separate explicit ceremony after verification."
printf '%s\n' ""
printf '%s\n' "After apply, freeze these non-secret identifiers as deployment evidence:"
printf '%s\n' "  ${AUTHORITY_SA}"
printf '%s\n' "  ${WORKER_SA}"
printf '%s\n' "  ${KEY_VERSION}"
printf '%s\n' "  gs://${PULPO_EVIDENCE_BUCKET}"
printf '%s\n' "  ${AUTHORITY_ORIGIN}"
printf '%s\n' "Then retrieve the KMS public key, convert it to the uncompressed P-256 SEC1 point, and compute the Pulpo-pinned SHA-256 fingerprint before any live signing path is enabled."
