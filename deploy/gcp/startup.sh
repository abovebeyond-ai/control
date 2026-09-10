#!/bin/bash
# First boot of a confidential VM on Google Cloud (Intel TDX): fetch the pinned
# gateway, generate its key on this disk, ask the hardware for a quote that
# binds the key, and serve. Runs as root from the instance metadata
# (startup-script); everything it makes belongs to the user "control".
#
# The binary is pinned by version and sha256, never "latest": the MRTD covers
# the VM image, but what runs inside it is this file's responsibility, and a
# verifier reading attestation.json deserves to know which build made it.
set -euo pipefail

RELEASE="${CONTROL_RELEASE:-v0.6.2}"
GATEWAY_SHA="${CONTROL_GATEWAY_SHA:-7d840a099b422adb71dca570671f1681f447f7bafd6917a2eaf5a7d0885d6edd}"
ISSUER="${CONTROL_ISSUER:-https://abovebeyond.ai/control/rehearsal}"
AGENT="${CONTROL_AGENT:-did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai#agent-rehearsal}"
PRINCIPAL="${CONTROL_PRINCIPAL:-did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai}"
# Where to listen. 127.0.0.1 for a rehearsal reached over ssh; 0.0.0.0 when a hand on
# another machine reaches it through Google's IAP tunnel (the firewall admits only
# 35.235.240.0/20 on the port, and the token below guards the submission).
# The listen address comes from the instance attribute control-listen; the client token
# from a file the operator placed in the secrets directory, never from metadata, which
# anyone with compute.viewer on the project can read.
meta() { curl -fsS -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1" 2>/dev/null || true; }
# The secrets come from Secret Manager, read with the VM's own service account, and land
# in the gateway user's directory at every boot: nobody copies a file in, and nobody needs
# a login to do so. A secret that is not there is simply absent (a token for an owner the
# grants do not name), except the client token, without which the gateway does not act.
fetch_secrets() {
  local project token
  project=$(curl -fsS -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/project-id)
  token=$(curl -fsS -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
  local names
  names=$(curl -fsS -H "Authorization: Bearer $token" "https://secretmanager.googleapis.com/v1/projects/$project/secrets?filter=name:control-" | python3 -c 'import sys,json; print("\n".join(s["name"].split("/")[-1] for s in json.load(sys.stdin).get("secrets",[])))')
  for n in $names; do
    local f="${n#control-}"
    curl -fsS -H "Authorization: Bearer $token" "https://secretmanager.googleapis.com/v1/projects/$project/secrets/$n/versions/latest:access" \
      | python3 -c 'import sys,json,base64; sys.stdout.write(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())' > "/var/lib/control/secrets/$f.tmp" \
      && mv "/var/lib/control/secrets/$f.tmp" "/var/lib/control/secrets/$f" && chmod 600 "/var/lib/control/secrets/$f" && chown control:control "/var/lib/control/secrets/$f" \
      || rm -f "/var/lib/control/secrets/$f.tmp"
  done
}
LISTEN="${CONTROL_LISTEN:-$(meta control-listen)}"; LISTEN="${LISTEN:-127.0.0.1:8471}"
CLIENT_TOKEN="${CONTROL_CLIENT_TOKEN:-}"

# Every boot runs all of this: it is idempotent, and a boot is how a carried
# configuration, a new secret or a new release takes effect without a login.

id control >/dev/null 2>&1 || useradd --system --home /var/lib/control --shell /usr/sbin/nologin control
install -d -o control -g control -m 750 /var/lib/control /var/lib/control/store
install -d -o control -g control -m 700 /var/lib/control/secrets
fetch_secrets || echo "secrets could not be fetched; whatever is on disk stays"
[ -z "$CLIENT_TOKEN" ] && [ -f /var/lib/control/secrets/client-token ] && CLIENT_TOKEN="$(cat /var/lib/control/secrets/client-token)"

if ! echo "${GATEWAY_SHA}  /usr/local/bin/control-gateway" | sha256sum -c - >/dev/null 2>&1; then
  tmp=$(mktemp)
  curl -fsSL -o "$tmp" "https://github.com/abovebeyond-ai/control/releases/download/${RELEASE}/control-gateway-linux-amd64"
  echo "${GATEWAY_SHA}  ${tmp}" | sha256sum -c - >/dev/null
  install -m 755 "$tmp" /usr/local/bin/control-gateway
  rm -f "$tmp"
  echo "installed control gateway ${RELEASE}"
fi

# Dry: judge, record, attest; perform nothing. A rehearsal proves the quote and
# the chain, it has no business touching a repository.
# The policy the operator carried (rehearse.sh config) lives in the instance attribute
# control-config and is applied at every boot, with what belongs to this machine set here:
# nobody needs to be inside to change what the gateway may judge. Without it, the
# rehearsal configuration below.
CARRIED="$(meta control-config)"
if [ -n "$CARRIED" ]; then
  printf '%s' "$CARRIED" | python3 -c "
import json,sys
c=json.load(sys.stdin)
c.update({'listen':'$LISTEN','store':'/var/lib/control/store','secrets':'/var/lib/control/secrets','attestation':'tdx','client_token':'$CLIENT_TOKEN','carried_over':True})
json.dump(c, open('/var/lib/control/config.json','w'), indent=2)
"
  echo "configuration taken from the instance attribute control-config"
elif [ -f /var/lib/control/config.json ] && grep -q '"carried_over": true' /var/lib/control/config.json; then
  echo "configuration carried over by the operator, left as is"
else
cat > /var/lib/control/config.json <<JSON
{
  "listen": "${LISTEN}",
  "client_token": "${CLIENT_TOKEN}",
  "issuer": "${ISSUER}",
  "store": "/var/lib/control/store",
  "secrets": "/var/lib/control/secrets",
  "dry": true,
  "attestation": "tdx",
  "agents": {
    "${AGENT}": {
      "grant": {
        "principal": "${PRINCIPAL}",
        "kinds": ["pull.open"],
        "resources": ["abovebeyond-ai/control"],
        "max_per_kind": 1
      }
    }
  }
}
JSON
fi
chown control:control /var/lib/control/config.json

# The quote door. On this kernel (7.0, Ubuntu 24.04 on GCP) quotes come only
# through configfs-tsm, and every report entry it creates is root-only; the
# older /dev/tdx_guest device makes reports, not quotes. So the unit acquires
# the quote as root in ExecStartPre (the "+" prefix), hands the key and the
# record to the gateway's user, and the gateway then runs unprivileged and
# accepts only a record that binds its own key.

cat > /etc/systemd/system/control-gateway.service <<'UNIT'
[Unit]
Description=control gateway (Proof-of-Control reference, attested)
After=network-online.target
Wants=network-online.target

[Service]
User=control
Group=control
ExecStartPre=+/usr/local/bin/control-gateway --config /var/lib/control/config.json --attest
ExecStartPre=+/bin/chown -R control:control /var/lib/control/secrets /var/lib/control/store
ExecStart=/usr/local/bin/control-gateway --config /var/lib/control/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/control
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

# The attestation refresh interval (row 7.2.3): the quote is retaken every day, and the
# gateway restarts on it, so no record rests on a measurement older than a day. A retake
# that fails leaves the gateway stopped: it does not continue on a stale measurement.
cat > /etc/systemd/system/control-attest.service <<'UNIT'
[Unit]
Description=control gateway: retake the hardware quote and restart on it

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/local/bin/control-gateway --config /var/lib/control/config.json --attest && systemctl restart control-gateway || systemctl stop control-gateway'
UNIT
cat > /etc/systemd/system/control-attest.timer <<'UNIT'
[Unit]
Description=daily attestation refresh of the control gateway

[Timer]
OnCalendar=*-*-* 05:50:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now control-attest.timer
systemctl enable control-gateway
systemctl restart control-gateway
sleep 3
systemctl --no-pager status control-gateway | head -5
curl -fsS http://127.0.0.1:8471/v1/key || true
