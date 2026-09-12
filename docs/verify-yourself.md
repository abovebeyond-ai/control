# Verify it yourself

Row 8.1.5 of the standard: an external party can obtain the evidence and complete the
verification using only published materials and no operator credentials. This page is
those materials. Nothing here needs an account, a key or a word from Above Beyond; a
machine with git, Go 1.22 or later, curl and python3 is enough.

Keep the terminal output with the date: that is the recorded run. Or let GitHub keep it: fork
https://github.com/abovebeyond-ai/verify-abovebeyond, switch Actions on, and your fork runs the
same steps daily on GitHub's machines and writes the verdict under your account.

```sh
# 1. The evidence: the public mirror of what the gateway wrote.
git clone https://github.com/abovebeyond-ai/control-evidence.git
# 2. The tooling: the verifier, from source, at the tag the README of the mirror names.
git clone https://github.com/abovebeyond-ai/control.git
# 3. The key: not from the mirror, from the identity log at abovebeyond.ai. The signer of
#    the records is the gateway, published as #control-gateway in the did:webvh document.
KEY=$(curl -fsS https://abovebeyond.ai/.well-known/did.json | python3 -c '
import sys, json, base64
doc = json.load(sys.stdin)
for m in doc["verificationMethod"]:
    if m["id"].endswith("#control-gateway"):
        x = m["publicKeyJwk"]["x"]
        print(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)).hex())')
echo "gateway key from the DID log: $KEY"
# 4. Verify: chain, three records per action, premises replayed, attestation under
#    Intel's roots, anchors, and that the anchored attestation is the one presented.
#    Since v0.15.0 also the machine's layers: the firmware against Google's signed
#    endorsement, the boot log replayed to RTMR0-2, and RTMR3 against the gateway's
#    own binary (the release asset, hashed here) and carried configuration.
RELEASE=$(grep -o 'CONTROL_RELEASE:-v[0-9.]*' control/deploy/gcp/startup.sh | cut -d- -f2)
curl -fsSL -o /tmp/control-gateway-linux-amd64 "https://github.com/abovebeyond-ai/control/releases/download/$RELEASE/control-gateway-linux-amd64"
cd control && go run ./cmd/verify \
  --store ../control-evidence/store \
  --key "$KEY" \
  --anchors ../control-evidence/anchors \
  --attestation ../control-evidence/store/attestation.json \
  --release-sha384 "$(sha384sum /tmp/control-gateway-linux-amd64 | cut -d' ' -f1)"
```

The layers are explained, with what each rests on, in `conformance/machine-image.md`.

Drop `--offline` in when the machine has no network for Intel's collateral or the Hedera
mirror node; the signatures, chains and receipts still verify, the freshness of the
collateral does not.

What "holds" means, and does not: the records were not altered after the gateway wrote
them, every judgement replays from the material beside it, the key that signed lives in
the measured environment the quote names, and the chain extends what was anchored. It does
not mean any repair was correct. Whether a judgement was wise is a person's reading.

A line `holds … record(s) name their bill of materials` means the digest in those records
resolves to a manifest kept beside them (`agbom/<step>.json`): what software, which commit,
which runner, which model if any. Records from before 11 September 2026 have none.

If a line says BROKEN, tell us, and tell the Society: that is the point of publishing it.

## The did:webvh log itself

The key above comes from `did.json`, which is derived from `did.jsonl`, the signed history.
To verify the history rather than trust the derived document, the site's repository
carries `scripts/did-webvh.mjs verify` (didwebvh-ts, DIF); it replays every version and
its signature from the first entry, whose hash is the identifier.

That proves nobody else wrote the log. It does not prove the operator wrote only one: a
second history, signed with the same key and shown to a different reader, replays just as
well. So every version's identifier is also posted to the public ledger, the same Hedera
topic as the checkpoints, and you can read the topic back without any receipt of ours:

```
go run ./cmd/anchor identity check --log https://abovebeyond.ai/.well-known/did.jsonl \
  --out /nonexistent --hedera testnet.json
```

where `testnet.json` is `{"network":"testnet","topicId":"0.0.10275637"}`; no account is
needed to read. The checker keeps the FIRST message the ledger holds for each version
number of this DID and compares it with the log you fetched. `holds` means the log you see
is the one first published, version by version. `two histories` means it is not. A version
that was never posted is named as well: the operator does not get to skip the ledger for a
version it would rather nobody saw. The receipts we keep, one per version at DigiCert and
on Hedera, are in the public copy under `anchors/identity/`; with `--out` pointing at them
the same command checks those too, offline with `--offline`.
