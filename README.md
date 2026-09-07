# control

A reference gateway service for the [Proof-of-Control Standard](https://github.com/AAI-Society/ov-poc-standard):
the thing you deploy once and point every agent at. Hands propose; the gateway judges,
writes the evidence, and performs the effect with credentials the hands never see.

The standard has a reference *library* in Python that demonstrates the protocol. This is a
reference *service*: one static binary, one configuration, one API, built so that moving it
into a confidential VM is a redeploy and not a rewrite.

## The boundary rule

Inside the trusted, measured core lives only what can change a verdict or hold a credential:
policy evaluation, the evidence log, the signing key, the effect adapters, and the premises
verifier. Everything else lives outside and needs no trust: anchorers, witnesses, verifiers,
dashboards. The gateway publishes a signed checkpoint; whoever anchors it to a ledger, a
timestamp authority or a witness reads that checkpoint and can prove nothing false, only
fail to anchor, which the verifier detects. That is how transparency systems that have met
attackers are built, and it is what the standard's rows on independent monitors describe.

## What one step does

1. **Premises first.** A kind the grant marks `premises_for` must carry a certificate of
   premises: a [ProveML](https://github.com/abovebeyond-ai/proveml) text stating why, every
   number a claim on a named record, every judgement a threshold from a registry declared in
   advance, with a provenance grade per fact. Verified inside the boundary with
   [proveml-go](https://github.com/abovebeyond-ai/proveml-go). A certificate that does not
   verify is a DENY before the grant is read; the seven claims of the reason-as-evidence
   profile ride in the token, the material sits beside the record.
2. **Then the grant**, path-aware: kinds, resources, how many of each in one path.
3. **Chain, tree, token.** The snapshot is committed to a hash chain and an RFC 6962 tree;
   the token is the standard's claim set, EdDSA over its canonical form (RFC 8785).
4. **Written before released.** The record is fsynced under a lock before the answer;
   an unwritable store answers FAIL_CLOSED and nothing leaves.
5. **The effect**, by an adapter holding the credential: GitHub first.

## Run it

```
go build ./cmd/gateway ./cmd/verify
./gateway --config config.json
```

```json
{
  "listen": "127.0.0.1:8471",
  "issuer": "https://portal.example/control",
  "store": "/var/lib/control/store",
  "secrets": "/etc/control/secrets",
  "dry": false,
  "agents": {
    "did:webvh:…:example.org#agent-fix": {
      "grant": { "principal": "did:webvh:…:example.org", "kinds": ["workflow.dispatch", "pull.open"],
                 "resources": ["owner/repo"], "max_per_kind": 1, "premises_for": ["workflow.dispatch"] }
    }
  }
}
```

The signing key is made on first start in the secrets directory, owner-only; GitHub tokens
live there as `github-token-<owner>`. `dry: true` judges and records but performs nothing,
for a first deployment beside an existing hand.

| method | what |
| --- | --- |
| `POST /v1/submit` | `{agent, principal, action:{kind,resource,params}, extension, premises}` → verdict, reason, step, token, effect |
| `GET /v1/checkpoint?agent=` | the signed tree head an anchorer or witness picks up |
| `GET /v1/records?agent=&from=` | the records, for a verifier |
| `GET /v1/proof?agent=&step=` | an inclusion proof against the current tree |
| `GET /v1/key` | the public key and issuer |

`verify --store DIR --key HEX [--checkpoint FILE]` replays everything with nothing but the
store, the public key and the measurement.

## Checked against what is not ours

`go test ./...` proves the pieces against the standard's own vectors: the canonical form
byte for byte, its published tokens re-signed identically under its published seed, the
tree against the RFC's recursive definition. `tools/crosscheck.py` then replays a chain
this gateway wrote with the standard's validator, its reference verifier, and the ProveML
JavaScript package as a second judge of every certificate, none of which is this
repository's code. CI runs both.

## What it is, no larger than the evidence supports

Software attestation. The standard's own validator says it on every token: platform
SOFTWARE, Tier 2 at most. The records prove they were not altered after the gateway wrote
them, that the chain is whole, and that a stranger can replay every judgement; they do not
yet prove the operator could not have written them differently. Tier 3 is the same binary
in a confidential VM, the key generated inside and bound to the attestation. Everything in
this repository is built for that move to change the `platform` claim and nothing else.

Apache-2.0. Offered to the Advanced AI Society as a lab project beside the
reason-as-evidence profile.
