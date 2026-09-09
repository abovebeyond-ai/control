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

RELEASE="${CONTROL_RELEASE:-v0.2.1}"
GATEWAY_SHA="${CONTROL_GATEWAY_SHA:-1fb2f976992778d33ea147ff90d19b892eac6fd768f6a6ffe29c128828d11a26}"
ISSUER="${CONTROL_ISSUER:-https://abovebeyond.ai/control/rehearsal}"
AGENT="${CONTROL_AGENT:-did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai#agent-rehearsal}"
PRINCIPAL="${CONTROL_PRINCIPAL:-did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai}"

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
  "listen": "127.0.0.1:8471",
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

# The quote door. configfs-tsm exists on this kernel but every report entry
# it creates is root-only, so an unprivileged gateway cannot use it; the older
# /dev/tdx_guest device takes a group and a mode, and a udev rule keeps them
# across reboots. The gateway tries configfs first and falls back to the device.
cat > /etc/udev/rules.d/80-tdx-guest.rules <<'RULE'
KERNEL=="tdx_guest", GROUP="control", MODE="0660"
RULE
udevadm control --reload-rules && udevadm trigger --name-match=tdx_guest || true
[ -e /dev/tdx_guest ] && chgrp control /dev/tdx_guest && chmod 660 /dev/tdx_guest || true

cat > /etc/systemd/system/control-gateway.service <<'UNIT'
[Unit]
Description=control gateway (Proof-of-Control reference, attested)
After=network-online.target
Wants=network-online.target

[Service]
User=control
Group=control
ExecStart=/usr/local/bin/control-gateway --config /var/lib/control/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/control /sys/kernel/config
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now control-gateway
sleep 3
systemctl --no-pager status control-gateway | head -5
curl -fsS http://127.0.0.1:8471/v1/key || true
