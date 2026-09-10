# Verify it yourself

Row 8.1.5 of the standard: an external party can obtain the evidence and complete the
verification using only published materials and no operator credentials. This page is
those materials. Nothing here needs an account, a key or a word from Above Beyond; a
machine with git, Go 1.22 or later, curl and python3 is enough.

Keep the terminal output with the date: that is the recorded run.

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
cd control && go run ./cmd/verify \
  --store ../control-evidence/store \
  --key "$KEY" \
  --anchors ../control-evidence/anchors \
  --attestation ../control-evidence/store/attestation.json
```

Drop `--offline` in when the machine has no network for Intel's collateral or the Hedera
mirror node; the signatures, chains and receipts still verify, the freshness of the
collateral does not.

What "holds" means, and does not: the records were not altered after the gateway wrote
them, every judgement replays from the material beside it, the key that signed lives in
the measured environment the quote names, and the chain extends what was anchored. It does
not mean any repair was correct. Whether a judgement was wise is a person's reading.

If a line says BROKEN, tell us, and tell the Society: that is the point of publishing it.

## The did:webvh log itself

The key above comes from `did.json`, which is derived from `did.jsonl`, the signed history.
To verify the history rather than trust the derived document, the site's repository
carries `scripts/did-webvh.mjs verify` (didwebvh-ts, DIF); it replays every version and
its signature from the first entry, whose hash is the identifier.
