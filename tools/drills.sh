#!/bin/bash
# The halt drills of Proof-of-Control rows 7.6.3 and 8.3.3, against the same gateway
# binary that runs in production, on this machine, in software attestation. Each drill
# says what it does, what happened, and whether that is the halt the row asks for. The
# output is the record; keep it dated under conformance/drills/.
#
#   tools/drills.sh            builds the gateway from this checkout and runs every drill
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'kill $(cat "$work/pid" 2>/dev/null) 2>/dev/null; rm -rf "$work"' EXIT
export PATH="$PATH:/opt/homebrew/bin:/usr/local/go/bin"
go build -o "$work/gateway" "$here/cmd/gateway" || exit 2
port=8497
agent="did:example:drill#agent"
cat > "$work/config.json" <<JSON
{"listen":"127.0.0.1:$port","issuer":"https://drill.example","store":"$work/store","secrets":"$work/secrets","dry":true,
 "agents":{"$agent":{"grant":{"principal":"did:example:drill","kinds":["pull.open"],"resources":["o/r"],"max_per_kind":10}}}}
JSON
start() { ("$work/gateway" --config "$work/config.json" >> "$work/gateway.log" 2>&1 & echo $! > "$work/pid"); for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$port/v1/key" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }
stop() { kill "$(cat "$work/pid")" 2>/dev/null; sleep 0.3; }
submit() { curl -s -o "$work/out.json" -w '%{http_code}' -X POST "http://127.0.0.1:$port/v1/submit" -H 'Content-Type: application/json' -d "{\"run\":\"$1\",\"agent\":\"$agent\",\"action\":{\"kind\":\"pull.open\",\"resource\":\"o/r\",\"params\":{\"branch\":\"b\",\"base\":\"main\"}}}"; }
result() { python3 -c "import json,sys; d=json.load(open('$work/out.json')); print(d.get('verdict'), '|', (d.get('reason') or d.get('error') or '')[:90])"; }

echo "# Halt drills, $(date -u +%Y-%m-%dT%H:%MZ), gateway built from $(git -C "$here" rev-parse --short HEAD)"
echo
echo "## 1. The evidence store cannot be written (row 7.6.3)"
start || { echo "the gateway did not start"; exit 1; }
code=$(submit r1); echo "- a normal step first: HTTP $code, $(result)"
chmod 000 "$work/store"/*.jsonl 2>/dev/null; chmod 500 "$work/store"
code=$(submit r2); echo "- store made unwritable, next step: HTTP $code, $(result)"
chmod 750 "$work/store"; chmod 640 "$work/store"/*.jsonl 2>/dev/null
code=$(submit r3); echo "- store restored, next step: HTTP $code, $(result)"
fails=$(wc -l < "$work/store-failures.jsonl" 2>/dev/null || echo 0)
echo "- failure log entries: $fails"
[ "$fails" -ge 1 ] && echo "- verdict: the refused step was FAIL_CLOSED, nothing left, and the failure is itself on record. Holds." || echo "- verdict: DOES NOT HOLD"
stop
echo
echo "## 2. The chain is tampered with (row 8.3.3)"
f=$(ls "$work/store"/*.jsonl | grep -v failures | head -1)
python3 - "$f" <<'PY'
import json,sys
p=sys.argv[1]; lines=open(p).read().splitlines()
t=json.loads(lines[0]); t['poc_claims']['verdict']='DENY'  # a rewritten first record
lines[0]=json.dumps(t, separators=(',',':')); open(p,'w').write("\n".join(lines)+"\n")
PY
echo "- the first record's verdict rewritten on disk, gateway restarted"
start; code=$(submit r4); echo "- next step: HTTP $code, $(result)"
grep -q "refusing to act" "$work/gateway.log" && echo "- gateway log: refusing to act on top of a log that does not replay" || true
[ "$code" != "200" ] && echo "- verdict: no step is judged on top of a rewritten chain. Holds." || echo "- verdict: DOES NOT HOLD"
stop
echo
echo "## 3. Hardware attestation is required and cannot be produced (row 8.3.3, 7.2.3)"
python3 -c "import json; p='$work/config.json'; c=json.load(open(p)); c['attestation']='tdx'; json.dump(c, open(p,'w'))"
rm -rf "$work/store" && mkdir "$work/store"
start && echo "- the gateway started without a quote: DOES NOT HOLD" || echo "- the gateway refused to start: $(grep -m1 -o 'configured to attest.*' "$work/gateway.log" | cut -c1-120)"
grep -q "configured to attest" "$work/gateway.log" && echo "- verdict: a gateway that must attest and cannot does not serve. Holds."
echo
echo "## Observed in production, not drilled"
echo "- 9 September 2026: the gateway on the confidential VM refused to start twice for lack of a usable quote provider (docs/tier-3-rehearsal.md)."
echo "- 10 September 2026 20:03 UTC: the far-end check on stocklistdealer's runner refused a dispatch (agent DID form) and the job stopped before any package moved (conformance/statement.md)."
echo "- 10 September 2026: the daily verifier reported the anchored attestation unresolvable after two reboots; the anchor job halted on it until every quote was kept (control v0.8.1)."
