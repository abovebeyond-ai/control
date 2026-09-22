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
   an unwritable store answers FAIL_CLOSED and nothing leaves. Since 22 September 2026 the
   chain is held to itself before every judgement as well: the tail of the store has to
   still carry the head this gateway holds, signed by its key, and if it does not, the
   action is refused rather than recorded. See `docs/the-halt.md` for the halt conditions
   and how to recover.
5. **The effect**, by an adapter holding the credential. Three adapters: GitHub
   (`workflow.dispatch`, `branch.push`, `branch.delete`, `pull.open`, `pull.ready`, since
   v0.26.0 `preview.push` and since v0.28.0 `issue.open` on `owner/repo`, one token per owner or the App), since 13 September
   2026 Portal (`portal.update`, `portal.time_entry`, `portal.expense`, `portal.project.patch`,
   `portal.task`, `portal.measure`, `portal.playbook` on `portal:<slug>`, the ingest token
   `portal-token`), and since v0.26.0 Forge (`forge.deploy` on `forge:<slug>`, the site's
   tokenless deploy trigger URL as `forge-deploy-<slug>`; see `docs/preview.md`).
   Since v0.18.0 an expense may carry its invoice attached, digest bound like a push's files, so no
   write of a session is left outside. The Portal adapter exists because the writes of a session to the operator's own
   dashboard went on the operator's token, from the session's machine, with no record: the
   same hand without evidence the GitHub adapter had replaced for pushes. The record and
   the capability travel with each write as `Control-Evidence` and `Control-Capability`
   headers, so Portal can keep them beside what was written.

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

The signing key is made on first start in the secrets directory, owner-only. On GitHub the
gateway acts as its own **GitHub App** when `github-app-id` and `github-app-key` (the App's
PEM key) are in that directory: it mints an installation token per owner at the moment of
the effect, GitHub attributes the work to `<app>[bot]`, and the owner is free to be the
reviewer branch protection demands. Without the App, or on an owner that has not installed
it, a token per owner as `github-token-<owner>` carries the effect instead; the refusal
names both roads when neither is there. `dry: true` judges and records but performs
nothing, for a first deployment beside an existing hand.

| method | what |
| --- | --- |
| `POST /v1/submit` | `{run, agent, principal, action:{kind,resource,params}, extension, premises}` → verdict, reason, step, action, token, effect, steps. Path limits count per `run`; a hand that names none has one run for life. One action is three records under one `control_action`: the request as judged, the effect as performed, the result as returned (row 7.1.2). |
| `GET /v1/github/read-token?owner=` | behind the client token: the App's installation token for that owner, downscoped to reading (contents, metadata, actions, pull requests), an hour long; only for owners the grants name. How the measuring side reads GitHub without tokens of its own (since v0.25.0). Not an effect, so not judged and not recorded. |
| `GET /v1/checkpoint?agent=` | the signed tree head an anchorer or witness picks up |
| `GET /v1/records?agent=&from=` | the records, for a verifier |
| `GET /v1/proof?agent=&step=` | an inclusion proof against the current tree |
| `GET /v1/agents` | the agents this gateway judges for, a digest of each grant's kinds and resources, the platform, and whether it is dry |
| `GET /v1/attachment?agent=&step=&name=` | what was written beside a record: `premises` or `action` |
| `GET /v1/key` | the public key, issuer and platform |
| `GET /v1/attestation` | the hardware's record binding the key, or 404 when software attests |

A grant may name the hand's own public key as `submitter_key`: every submission must then
be signed by it, `Control-Signature` carrying the Ed25519 signature over the request body in
hex, and the record says `control_submitter: verified`; an unsigned or wrongly signed
submission is refused and the refusal recorded (row 5.1.2). Parameters are held to a schema
per kind (row 4.1.4).

A grant may name the principal's public key as `principal_key`: every submission must then
carry `capability`, a token the principal signed for the task (`capability` package: who,
for which agent and gateway, which kinds on which resources, until when), and the gateway
takes the intersection of grant and capability, so a capability narrows and never widens
(rows 4.2.1, 4.2.3, 5.1.3). The record carries the token's digest and the task it names.

A grant may also name the principal's further keys by DID fragment (`principal_keys`, since
v0.19.0): the operator's own key on a hardware token (`did:webvh:…#operator`) and its
counterpart on the second token (`#operator-2`). A capability whose issuer is one of them
is verified against that key, and the record's `control_task.iss` says which key spoke.
Until then every capability was signed by the application that issued it (Portal), so the
operator's word was whatever that application chose to sign; with the operator's keys named,
the word is a signature only the person holding the token could have made, and the issuing
application is a channel, not a trust root.

A grant may be per task (`tasks`, v0.18.0): one hand that runs several playbooks under one
key is one agent, not several, because the key is what a stranger can check and several
agent ids on one key would claim a boundary that does not exist. The agent then holds one
grant, and the task the capability names (`task.playbook`) selects that task's own verbs,
`premises_for` and `judgements` out of it; a task's kinds are met with the grant's, so a task
never widens. A capability naming a task the grant does not have, or no capability at all,
is refused and recorded. The bundle carries the tasks, the record names the task.

`client_token` in the configuration, when set, is what a hand must present as a bearer
token to submit: a gateway reached from another machine holds credentials and judges within
grants, and without it anyone who can reach the port could make it act. Reading stays open;
evidence is for strangers.

`docs/verify-yourself.md` is the recipe for a stranger: the mirror, this verifier, and the
key from the DID log, no credentials. `verify --gateway URL` reads everything from a running gateway over HTTP, agents, records,
attachments, attestation and the live checkpoint, so a stranger verifies without the store
directory; `--key` holds it to a key obtained elsewhere, such as the DID document.
`verify --store DIR --key HEX [--checkpoint FILE] [--anchors DIR]` replays everything with
nothing but the store, the public key and the measurement, and, given the receipts, that
the chain extends every anchored head.

## Anchoring, outside

`anchor` is a separate binary that never holds a key. It reads the signed checkpoint from
the gateway, verifies the signature under the key the gateway publishes, posts the
checkpoint bytes to a backend, and keeps what the backend answered as a receipt, one per
tree size and backend. A size already anchored is skipped, so running it every minute
costs nothing when nothing moved.

```
anchor pin --gateway http://127.0.0.1:8471 --agent DID --out anchors --tsa http://timestamp.digicert.com
anchor pin --gateway http://127.0.0.1:8471 --agent DID --out anchors --hedera operator.json
anchor check --out anchors --agent DID --key HEX [--offline]
```

Two backends from the start, so that no ledger is load-bearing and a third is an
afternoon: an **RFC 3161 timestamp authority** (a signed timestamp over the checkpoint's
hash from a public authority, no account, verified offline against the certificate in the
token) and **Hedera Consensus Service** (a consensus timestamp from a public ledger, kept as
the mirror node returned it). The standard accepts either, and running both makes
presenting two histories to two readers a matter of forging two independent parties.

What this design gives up on purpose: nothing inside the gateway knows a ledger exists.
A client who wants the anchor inside their own consortium chain writes a backend against
this interface and never touches the measured core.

## Checked against what is not ours

`go test ./...` proves the pieces against the standard's own vectors: the canonical form
byte for byte, its published tokens re-signed identically under its published seed, the
tree against the RFC's recursive definition. `tools/crosscheck.py` then replays a chain
this gateway wrote with the standard's validator, its reference verifier, and the ProveML
JavaScript package as a second judge of every certificate, none of which is this
repository's code. CI runs both.

## What it is, no larger than the evidence supports

Hardware attestation, on a machine nobody can log into. The gateway asks Intel TDX for a
quote at start and refuses to run without one; REPORTDATA is SHA-512 of
`poc-evidence-key\0` and the public key, so the hardware's signature covers both the code
that runs and the key it holds. Every token says platform INTEL_TDX. Measured on
22 September 2026:

```
release     v0.30.0 sha256:e0106215f9ef8919a2d51980b876ee21c96aa263e2d22aa73952c7c15accf044
platform    INTEL_TDX (configfs-tsm)
mrtd        c1ee9c16e3afc506cfe042c5b846a368...
rtmr3       28e1098712a03dade4878ed2ad2970f0...
  input     control-gateway-linux-amd64  sha-384:02694066e9075eb5...
  input     carried-config               sha-384:3e1db14d33738dd2...
```

**The measurement in a token is the MRTD, and the MRTD is not the binary.** It is a
SHA-384 of the initial contents of the trust domain, so it does not move when the pinned
release does, which is what lets a chain survive an upgrade instead of demanding a
rotation. The binary and the operator's carried configuration are extended into RTMR3
instead, and the record names both with their digests; `verify --release-sha384` holds
RTMR3 to the published release asset. On the record above that digest matches the
`control-gateway-linux-amd64` asset of v0.30.0 exactly.

The records are Tier 3: hash chained, an RFC 6962 tree, the head posted daily to Hedera
mainnet topic 0.0.10856156 by an anchorer trusted with nothing else, mirrored publicly at
`abovebeyond-ai/control-evidence`, with the keys in the DID log and `cmd/verify` usable
without any credential of ours. Nobody has to take our word for a judgement; they replay
it.

Two Tier 4 rows hold as well, since v0.30.0. Before it judges anything the gateway holds
the tail of its own log against the head it carries, and it verifies every record of that
log under its own key; when those disagree it answers FAIL_CLOSED and stops, which is
C7.6.3 and C8.3.3. The halt conditions, the recovery and the tolerable outage are in
[docs/the-halt.md](docs/the-halt.md); there is no override flag.

**What still caps the claim.** C8.3.2 grades a chain by the weakest interaction it shares,
and the admission is the weak one: a capability is normally signed by `#portal`, an Ed25519
key in the environment of an ordinary server, so whoever holds that server can mint one.
Signing it on the operator's token instead (`hand.mjs admit`, `#operator`) is the move that
lifts that interaction, and until it is the rule rather than the alternative, a claim about
a whole run is Tier 2 even though the records are Tier 3. Also missing for Tier 4: the
interaction inventory of C8.3.1, enforcement at the far end in C8.3.5, which GitHub will
not do for us, the per-record validator of C10.3.3, and the third-party reassessment of
C10.3.5.

Apache-2.0. Offered to the Advanced AI Society as a lab project beside the
reason-as-evidence profile.
