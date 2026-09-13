#!/bin/bash
# The Tier 3 rehearsal from the Mac: create the confidential VM, let the startup
# script bring up an attested gateway, submit one dry action, bring the
# attestation, the key and the record home, and verify them here with
# collateral from Intel. Stop the VM at the end; you pay for the disk only.
#
#   deploy/gcp/rehearse.sh create | submit | fetch | verify | stop | start | delete | config FILE
#   deploy/gcp/rehearse.sh tokens | live | dry        (the service-mode switch, and its reverse)
#   deploy/gcp/rehearse.sh lockdown | breakglass | reboot | reset | serial   (custody: no login, ever, except on purpose; reboot is stop+start, reset a power cut)
#   deploy/gcp/rehearse.sh principal <hex>                           (the principal's ticket key changed; applies with a reboot)
#   deploy/gcp/rehearse.sh upgrade                                   (carry startup.sh with its pinned release and reboot)
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
  # The image by name, not by family (since 12 September 2026): the boot chain the
  # quote's RTMR1 and RTMR2 measure is that image's shim, grub, kernel and initrd,
  # and a reference value needs a fixed thing to point at. conformance/machine-image.md
  # names the image the production machine runs; change both together.
  $G instances create "$NAME" --zone "$ZONE" \
    --machine-type c3-standard-4 --confidential-compute-type TDX \
    --maintenance-policy TERMINATE --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
    --image "${CONTROL_GCP_IMAGE:-ubuntu-2404-noble-amd64-v20260906}" --image-project ubuntu-os-cloud \
    --boot-disk-size 20GB --no-address \
    --service-account "control-gateway-vm@$PROJECT.iam.gserviceaccount.com" --scopes cloud-platform \
    --metadata control-listen=0.0.0.0:8471 \
    --metadata-from-file startup-script="$here/startup.sh"
  # The service account is the one Secret Manager lets read the tokens, and the listen
  # address is what the tunnel from the box expects; the production machine had both set
  # by hand, and a rebuild from this step alone would have come up deaf and without
  # tokens (found writing docs/rebuild.md, 13 September 2026). Then: config, tokens, lockdown.
  echo "created without a public address; next: $0 config FILE, $0 tokens, $0 reboot, $0 lockdown (docs/rebuild.md)"
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
  # and their grants) to the VM as the instance attribute control-config; the boot script
  # applies it with what belongs to the VM (listen, store, secrets, attestation, the token
  # from Secret Manager). A reboot applies it; nobody is inside.
  [ -f "${2:-}" ] || { echo "config FILE: the generated config.json"; exit 2; }
  python3 - "$2" > /tmp/control-config.json <<'PYCFG'
import json,sys
c=json.load(open(sys.argv[1]))
for k in ('listen','store','secrets','attestation','client_token','carried_over'): c.pop(k, None)
print(json.dumps(c, separators=(',',':')))
PYCFG
  $G instances add-metadata "$NAME" --zone "$ZONE" --metadata-from-file control-config=/tmp/control-config.json
  rm -f /tmp/control-config.json
  echo "carried; reboot to apply: $0 reboot"
  ;;
tokens)
  # The GitHub tokens go into Secret Manager, one secret each, readable by the VM's own
  # service account and nothing else; the boot script fetches them. Read from the box's
  # secrets, never stored on this machine.
  BOX="${CONTROL_BOX:-elixir@167.233.221.164}"
  for f in client-token $(ssh "$BOX" 'ls /home/elixir/elixir-secrets/control/ | grep ^github-token-'); do
    n="control-$f"
    if gcloud --project="$PROJECT" secrets describe "$n" >/dev/null 2>&1; then
      ssh "$BOX" "cat /home/elixir/elixir-secrets/control/$f" | tr -d '\n' | gcloud --project="$PROJECT" secrets versions add "$n" --data-file=- >/dev/null && echo "updated $n"
    else
      ssh "$BOX" "cat /home/elixir/elixir-secrets/control/$f" | tr -d '\n' | gcloud --project="$PROJECT" secrets create "$n" --data-file=- --replication-policy=user-managed --locations="${ZONE%-*}" >/dev/null && echo "created $n"
      gcloud --project="$PROJECT" secrets add-iam-policy-binding "$n" --member "serviceAccount:control-gateway-vm@$PROJECT.iam.gserviceaccount.com" --role roles/secretmanager.secretAccessor >/dev/null
    fi
  done
  echo "reboot to apply: $0 reboot"
  ;;
live|dry)
  # Flip dry in the carried configuration (the instance attribute) and reboot to apply:
  # live performs, dry records only. No login needed.
  want=$([ "$1" = live ] && echo false || echo true)
  $G instances describe "$NAME" --zone "$ZONE" --format="value(metadata.items.control-config)" > /tmp/control-config.json
  [ -s /tmp/control-config.json ] || { echo "no carried configuration on the instance; run config first"; exit 2; }
  python3 - "$want" <<'PYDRY'
import json,sys
c=json.load(open('/tmp/control-config.json')); c['dry']=(sys.argv[1]=='true')
json.dump(c, open('/tmp/control-config.json','w'), separators=(',',':'))
PYDRY
  $G instances add-metadata "$NAME" --zone "$ZONE" --metadata-from-file control-config=/tmp/control-config.json
  rm -f /tmp/control-config.json
  "$0" reboot
  ;;
principal)
  # The principal's key changed (Portal's ticket key, 11 September 2026 into Cloud KMS):
  # set principal_key in every grant of the carried configuration and reboot to apply.
  # Tickets signed with the old key are refused from the reboot on, with a record.
  [ -n "$2" ] && [ "${#2}" -eq 64 ] || { echo "usage: $0 principal <ed25519 public key, 64 hex>"; exit 2; }
  $G instances describe "$NAME" --zone "$ZONE" --format="value(metadata.items.control-config)" > /tmp/control-config.json
  [ -s /tmp/control-config.json ] || { echo "no carried configuration on the instance; run config first"; exit 2; }
  python3 - "$2" <<'PYPRIN'
import json,sys
c=json.load(open('/tmp/control-config.json'))
for a,g in c.get('agents',{}).items():
    (g.get('grant') or g)['principal_key']=sys.argv[1]
json.dump(c, open('/tmp/control-config.json','w'), separators=(',',':'))
PYPRIN
  $G instances add-metadata "$NAME" --zone "$ZONE" --metadata-from-file control-config=/tmp/control-config.json
  rm -f /tmp/control-config.json
  "$0" reboot
  ;;
upgrade)
  # A new release: startup.sh pins RELEASE and GATEWAY_SHA; carry the script to the
  # instance and reboot, and the boot installs that release by checksum. No login.
  $G instances add-metadata "$NAME" --zone "$ZONE" --metadata-from-file startup-script="$here/startup.sh"
  echo "boot script carried: $(grep -o 'CONTROL_RELEASE:-v[0-9.]*' "$here/startup.sh")"
  "$0" reboot
  ;;
reboot)
  # A stop and a start, not a reset. A reset is a power cut: on 11 and 12 September 2026
  # every reset lost the attachments written in the minute before it (the records were
  # synced, the files beside them were not). A stop is an orderly shutdown that flushes
  # the disk; it takes a minute longer. The boot script then installs the pinned release.
  $G instances stop "$NAME" --zone "$ZONE" --quiet
  $G instances start "$NAME" --zone "$ZONE" --quiet
  echo "stopped and started; the gateway is back within two minutes (attestation, then serve)"
  ;;
reset)
  # The power cut, kept for when a stop hangs. Not for routine use.
  $G instances reset "$NAME" --zone "$ZONE"
  echo "reset; the gateway is back within a minute (attestation, then serve)"
  ;;
lockdown)
  # No path to a login: the SSH firewall rule goes; only Google's tunnel range reaches the
  # gateway port. Re-adding the rule is the break-glass, and Google's audit log records it.
  gcloud --project="$PROJECT" compute firewall-rules delete allow-iap-ssh --quiet && echo "ssh rule removed: no login path to the VM"
  ;;
breakglass)
  gcloud --project="$PROJECT" compute firewall-rules create allow-iap-ssh --network default --direction INGRESS --source-ranges 35.235.240.0/20 --allow tcp:22 --quiet && echo "ssh rule back: this is in the audit log; rotate the key after use"
  ;;
serial)
  # The boot log without a login: what the boot script and the gateway printed.
  $G instances get-serial-port-output "$NAME" --zone "$ZONE" 2>/dev/null | grep -i "startup-script\|control gateway\|attested\|secrets\|configuration" | tail -20
  ;;
stop)   $G instances stop "$NAME" --zone "$ZONE" ;;
start)  $G instances start "$NAME" --zone "$ZONE" ;;
delete) $G instances delete "$NAME" --zone "$ZONE" ;;
log)    $G ssh "$NAME" --zone "$ZONE" --tunnel-through-iap -- "sudo journalctl -u control-gateway --no-pager -n 50; sudo journalctl -u google-startup-scripts --no-pager -n 30" ;;
*) sed -n 2,12p "$0"; exit 2 ;;
esac
