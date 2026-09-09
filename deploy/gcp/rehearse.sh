#!/bin/bash
# The Tier 3 rehearsal from the Mac: create the confidential VM, let the startup
# script bring up an attested gateway, submit one dry action, bring the
# attestation, the key and the record home, and verify them here with
# collateral from Intel. Stop the VM at the end; you pay for the disk only.
#
#   deploy/gcp/rehearse.sh create | submit | fetch | verify | stop | start | delete
#
# Needs: gcloud (brew install --cask gcloud-cli), `gcloud auth login`, and
# PROJECT set below or in the environment.
set -euo pipefail
PROJECT="${CONTROL_GCP_PROJECT:?set CONTROL_GCP_PROJECT to the project id}"
ZONE="${CONTROL_GCP_ZONE:-europe-west4-a}"
NAME="${CONTROL_GCP_NAME:-control-gateway}"
OUT="${CONTROL_REHEARSAL_OUT:-$HOME/.config/proveml/rehearsal}"
AGENT="did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai#agent-rehearsal"
G="gcloud --project=$PROJECT compute"
here=$(cd "$(dirname "$0")" && pwd)

case "${1:-}" in
create)
  $G instances create "$NAME" --zone "$ZONE" \
    --machine-type c3-standard-4 --confidential-compute-type TDX \
    --maintenance-policy TERMINATE --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
    --boot-disk-size 20GB --no-address \
    --metadata-from-file startup-script="$here/startup.sh"
  echo "created without a public address; reach it with: gcloud compute ssh --tunnel-through-iap"
  ;;
submit)
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- \
    "curl -fsS -X POST http://127.0.0.1:8471/v1/submit -H 'Content-Type: application/json' -d '{\"agent\":\"$AGENT\",\"action\":{\"kind\":\"pull.open\",\"resource\":\"abovebeyond-ai/control\",\"parameters\":{\"title\":\"rehearsal\"}}}'"
  echo
  ;;
fetch)
  mkdir -p "$OUT/store"
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- \
    "sudo cat /var/lib/control/store/attestation.json" > "$OUT/store/attestation.json"
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- \
    "sudo ls /var/lib/control/store/*.jsonl | xargs -n1 basename" | while read -r f; do
    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo cat /var/lib/control/store/$f" > "$OUT/store/$f"
  done
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "curl -fsS http://127.0.0.1:8471/v1/key" > "$OUT/key.json"
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "curl -fsS 'http://127.0.0.1:8471/v1/checkpoint?agent=$AGENT'" > "$OUT/checkpoint.json"
  echo "brought home to $OUT"; ls -la "$OUT" "$OUT/store"
  ;;
verify)
  key=$(python3 -c "import json;print(json.load(open('$OUT/key.json'))['public_key'])")
  (cd "$here/../.." && go run ./cmd/verify --store "$OUT/store" --key "$key" \
     --attestation "$OUT/store/attestation.json" --checkpoint "$OUT/checkpoint.json")
  ;;
stop)   $G instances stop "$NAME" --zone "$ZONE" ;;
start)  $G instances start "$NAME" --zone "$ZONE" ;;
delete) $G instances delete "$NAME" --zone "$ZONE" ;;
log)    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo journalctl -u control-gateway --no-pager -n 50; sudo journalctl -u google-startup-scripts --no-pager -n 30" ;;
*) sed -n 2,12p "$0"; exit 2 ;;
esac
