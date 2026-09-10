#!/bin/bash
# The Tier 3 rehearsal from the Mac: create the confidential VM, let the startup
# script bring up an attested gateway, submit one dry action, bring the
# attestation, the key and the record home, and verify them here with
# collateral from Intel. Stop the VM at the end; you pay for the disk only.
#
#   deploy/gcp/rehearse.sh create | submit | fetch | verify | stop | start | delete | config FILE
#   deploy/gcp/rehearse.sh tokens | live | dry        (the service-mode switch, and its reverse)
#
# Needs: gcloud (brew install --cask gcloud-cli), `gcloud auth login`, and
# PROJECT set below or in the environment.
set -euo pipefail
PROJECT="${CONTROL_GCP_PROJECT:?set CONTROL_GCP_PROJECT to the project id}"
ZONE="${CONTROL_GCP_ZONE:-europe-west4-a}"
NAME="${CONTROL_GCP_NAME:-control-gateway}"
OUT="${CONTROL_REHEARSAL_OUT:-$HOME/.config/proveml/rehearsal}"
AGENT="did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai#agent-rehearsal"
AGENT_Q="${AGENT//#/%23}" # in a query string the fragment sign must be escaped
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
    "sudo sh -c 'ls /var/lib/control/store/*.jsonl' | xargs -n1 basename" | while read -r f; do
    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo cat /var/lib/control/store/$f" > "$OUT/store/$f"
  done
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "curl -fsS http://127.0.0.1:8471/v1/key" > "$OUT/key.json"
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "curl -fsS 'http://127.0.0.1:8471/v1/checkpoint?agent=$AGENT_Q'" > "$OUT/checkpoint.json"
  echo "brought home to $OUT"; ls -la "$OUT" "$OUT/store"
  ;;
verify)
  key=$(python3 -c "import json;print(json.load(open('$OUT/key.json'))['public_key'])")
  (cd "$here/../.." && go run ./cmd/verify --store "$OUT/store" --key "$key" \
     --attestation "$OUT/store/attestation.json" --checkpoint "$OUT/checkpoint.json")
  ;;
config)
  # Carry a configuration the hands generated (the box's control/config.json: the agents
  # and their grants) to the VM, with what belongs to the VM overriding: where it listens,
  # where its store and secrets are, that it attests, the client token from its secrets.
  # Dry stays as the file says; flipping it to act is a separate, deliberate edit.
  [ -f "${2:-}" ] || { echo "config FILE: the generated config.json"; exit 2; }
  python3 - "$2" > /tmp/control-config.json <<'PYCFG'
import json,sys
c=json.load(open(sys.argv[1]))
c.update({"listen":"0.0.0.0:8471","store":"/var/lib/control/store","secrets":"/var/lib/control/secrets","attestation":"tdx","client_token":"","carried_over":True})
print(json.dumps(c, indent=2))
PYCFG
  $G scp /tmp/control-config.json "$NAME":/tmp/control-config.json --zone "$ZONE" --tunnel-through-iap
  rm -f /tmp/control-config.json
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo python3 -c \"import json; c=json.load(open('/tmp/control-config.json')); c['client_token']=open('/var/lib/control/secrets/client-token').read().strip(); json.dump(c, open('/var/lib/control/config.json','w'), indent=2)\"; sudo chown control:control /var/lib/control/config.json; sudo chmod 640 /var/lib/control/config.json; rm /tmp/control-config.json; sudo systemctl restart control-gateway; sleep 3; curl -fsS http://127.0.0.1:8471/v1/agents"
  echo
  ;;
tokens)
  # The GitHub tokens move inside the boundary: read from the box's secrets, written into
  # the VM's secrets for the gateway's user, never stored on this machine. Service mode
  # is what makes the hands' own copies unnecessary; they are removed there by hand.
  BOX="${CONTROL_BOX:-elixir@167.233.221.164}"
  for f in $(ssh "$BOX" 'ls /home/elixir/elixir-secrets/control/ | grep ^github-token-'); do
    val=$(ssh "$BOX" "cat /home/elixir/elixir-secrets/control/$f")
    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "printf '%s' '$val' | sudo tee /var/lib/control/secrets/$f >/dev/null; sudo chown control:control /var/lib/control/secrets/$f; sudo chmod 600 /var/lib/control/secrets/$f" >/dev/null 2>&1
    echo "placed $f"
  done
  ;;
live|dry)
  # Flip dry in the carried configuration and restart: live performs, dry records only.
  want=$([ "$1" = live ] && echo False || echo True)  # a Python literal
  $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo python3 -c \"import json; p='/var/lib/control/config.json'; c=json.load(open(p)); c['dry']=$want; json.dump(c, open(p,'w'), indent=2)\"; sudo systemctl restart control-gateway; sleep 3; curl -fsS http://127.0.0.1:8471/v1/agents" 2>&1 | grep -v "^WARNING\|NumPy\|please see"
  echo
  ;;
stop)   $G instances stop "$NAME" --zone "$ZONE" ;;
start)  $G instances start "$NAME" --zone "$ZONE" ;;
delete) $G instances delete "$NAME" --zone "$ZONE" ;;
log)    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo journalctl -u control-gateway --no-pager -n 50; sudo journalctl -u google-startup-scripts --no-pager -n 30" ;;
*) sed -n 2,12p "$0"; exit 2 ;;
esac
