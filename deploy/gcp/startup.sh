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

RELEASE="${CONTROL_RELEASE:-v0.3.0}"
GATEWAY_SHA="${CONTROL_GATEWAY_SHA:-da12ac0bdd43f43978363189f177bc7d2c547f2c0969bb52fc0090727817d321}"
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
LISTEN="${CONTROL_LISTEN:-$(meta control-listen)}"; LISTEN="${LISTEN:-127.0.0.1:8471}"
CLIENT_TOKEN="${CONTROL_CLIENT_TOKEN:-}"
[ -z "$CLIENT_TOKEN" ] && [ -f /var/lib/control/secrets/client-token ] && CLIENT_TOKEN="$(cat /var/lib/control/secrets/client-token)"

if [ -x /usr/local/bin/control-gateway ] && systemctl is-active --quiet control-gateway; then
  echo "control gateway already installed and running"; exit 0
fi

id control >/dev/null 2>&1 || useradd --system --home /var/lib/control --shell /usr/sbin/nologin control
install -d -o control -g control -m 750 /var/lib/control /var/lib/control/store
install -d -o control -g control -m 700 /var/lib/control/secrets

tmp=$(mktemp)
curl -fsSL -o "$tmp" "https://github.com/abovebeyond-ai/control/releases/download/${RELEASE}/control-gateway-linux-amd64"
echo "${GATEWAY_SHA}  ${tmp}" | sha256sum -c - >/dev/null
install -m 755 "$tmp" /usr/local/bin/control-gateway
rm -f "$tmp"

# Dry: judge, record, attest; perform nothing. A rehearsal proves the quote and
# the chain, it has no business touching a repository.
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

systemctl daemon-reload
systemctl enable --now control-gateway
sleep 3
systemctl --no-pager status control-gateway | head -5
curl -fsS http://127.0.0.1:8471/v1/key || true
