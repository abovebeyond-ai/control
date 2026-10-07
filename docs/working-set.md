# The working set: one strong word, then a passkey wherever you are

Status: design note, 6 October 2026. Nothing here is built yet. It builds on `mandates.md`
(commands modelled on blast radius) and changes how the owner approves, not what a hand may do.

## Why

The owner works by voice as much as at a desk, and an approval that needs the laptop stops the
work wherever he is not at it. On 6 October 2026 that showed in three places:

- admissions per project for two hours or a day, so a task started by voice stalls on "not
  admitted" halfway;
- a grant change (a new command, a new project) that needs the laptop, a gcloud login, a copy
  of the configuration and a reboot of the gateway, and until then the gateway serves an older
  grant, sometimes a wider one; a gateway should not be restarted because its owner changed his
  mind, it should read what he signed;
- the choice between the YubiKey (strong, at the laptop) and the passkey (anywhere, but it ends
  at Portal's key, so Portal is trusted with the owner's word).

Approving often also wears the approval down: a word given without reading is worth nothing.

## The idea

The owner declares, once and with the strong key, what he is working on: which projects, up to
which blast radius, until when. Inside that boundary every approval is a passkey touch, on the
road or at the laptop. Outside it, the strong key again.

- **The working set** is signed on a YubiKey (`#operator`, `#operator-2`): projects, the highest
  layer (B1, B2, B3), an end (a week at most), and a jti. Portal keeps it and shows it; Portal
  cannot make or widen one.
- **Inside the set**, the passkey approves: admitting a project, a repair layer for the day, a
  grant change that adds a command at or below the set's layer, a single B3 action with its
  parameters. Each such approval names the working set it falls under (its jti).
- **Outside the set** (another project, a higher layer, after the end), the passkey is refused and
  the owner is asked for the strong key.
- **The standing yes per project** (lane 2) is the working set itself: no admissions every two
  hours.

## Why it holds

- **Portal cannot stretch the boundary.** A passkey approval ends at Portal's key, as today; what
  is new is that the gateway and the systems also check that it falls inside a working set signed
  on the owner's token, verified against the DID document. Someone who took over Portal can do at
  most what the owner already set out for that week, on those projects.
- **The chain ends at a person's key.** Every action points to a passkey approval, and that to a
  working set signed on a YubiKey. The workbench claim in the conformance statement (admitted by
  the operator in person, Tier 3) holds again for passkey approvals inside a set; it is Tier 2
  today.
- **Fewer, better approvals.** The owner thinks once about the week; after that he is asked only
  about concrete steps inside it.

## The gateway reads its policy

A grant change is not pushed into the gateway, and the gateway is not restarted because the
owner signed a different policy. The gateway reads its policy itself, as the systems read the
owner's DID document:

1. **A signed policy log.** Each version of the grants is a document signed by the owner (a
   passkey inside a working set, the strong key otherwise), with a version number and the hash
   of the version before it: the same shape as the DID log. Portal shows each new version as the
   difference in words ("new: the workbench may retry a report on the Gentells pipeline, B2")
   before the owner signs it.
2. **The gateway reads it every minute**, checks the signatures against the DID document and the
   working set, and applies a newer version. No inbound channel to the confidential VM, no
   gcloud, no reboot: the gateway only reaches out.
3. **Never backwards.** The gateway accepts only a higher version that names the hash of the one
   it holds. A replayed older version, wider or not, is refused.
4. **Narrowing needs no owner.** Elixir may write a version that only takes away (a project or a
   command removed); the gateway checks that it is narrower than the one it holds and applies it.
   The lag in which a removed project stayed allowed until the carry-over is gone.
5. **Every record names the policy version** it was judged under. The boot configuration stays
   measured in RTMR3; the log is the history of every change after it, and a reader replays both.

Where the log lives: grants name client repositories, so the documents are served by Portal to
the gateway and to a verifier with access, and only their hashes are public, anchored with the
chain heads (DigiCert and Hedera), so nobody can rewrite the history unseen.

## What changes where

- **control:** a working-set token and its check; the gateway reading a signed policy log at run
  time, forward only, a narrowing applied without the owner; the policy version on every record;
  the conformance statement's passkey row and grant rows.
- **Portal:** declaring a working set (signed on the token, through `hand.mjs` on the laptop, or
  WebAuthn with the YubiKey as a security key); passkey approvals that name their set; the grant
  difference in words; approving one B3 action from a push.
- **The systems:** verify that a mandate falls inside a working set, the same way they verify the
  mandate today.
- **The voice:** says what waits for a touch and whether it is inside the set; never asks for the
  touch itself.

## The policy log as built (7 October 2026)

The gateway half is in the code: `policy/log.go`, `cmd/gateway/policylog.go`, the RTMR3
extension in `attest/boot.go` and the `control-policy` timer in `deploy/gcp/startup.sh`.

**A version** is a token in the working set's form, `base64url(payload).base64url(Ed25519
signature)`, with the payload:

| field | meaning |
|---|---|
| `type` | `policy-version`, so a working set or a capability signed by the same key is never read as a policy |
| `iss` | the signer's DID URL |
| `version` | one more than the version served |
| `prev` | `sha-256:` of the previous token, or of the carried configuration for version 1 |
| `iat` | when it was signed; not more than five minutes ahead of the gateway's clock |
| `agents` | every hand's grant, in the shape `config.json` gives it |
| `systems` | the running systems' addresses |
| `change` | the change in the words the signer was shown before signing (row 4.1.6) |

**Who signs.** The carried configuration names the keys under `policy_log.signers`, and is
measured into RTMR3 with them. `widen` keys (the owner's tokens, `#operator`, `#operator-2`)
may sign any version. `narrow` keys (Elixir) may sign a version only if the gateway itself finds
it narrower: no new hand, kind, resource, task, system or accepted judgement; no higher count;
no certificate or per-action word dropped; no change to who speaks for a hand; no system moved
to another address. Anything else from a narrowing key is refused, by name.

**Forward only.** A version must carry the very next number and name the hash of the version
served. A replayed older version, a skipped number or a fork is refused. A refused version is not
kept, and every later version waits behind it until one that follows the served version arrives.

**How it is applied.** A root timer runs `control-gateway --pull-policy` every minute: it asks
`policy_log.url?after=<version>` with the gateway's Portal token (grants name client
repositories, so the log is not public), judges each version, and keeps those that hold in
`/var/lib/control/policy-log.json`. When it kept one it exits 3, and the unit restarts the
gateway. The restart's `--attest` extends RTMR3 with each applied version after the binary and
the carried configuration, in order (`attest.ExtendFrom` extends only what the register does not
hold yet), and takes a fresh quote before the first action under the version: an attestation on
every configuration change, held to the versions the owner signed (row 6.1.3). A verifier folds
RTMR3 from the record's named inputs, as it does today.

**On the record.** Every record carries `control_policy`, `v<n> sha-256:<hash>` (the carried
configuration is v0), beside `policy_bundle_hash`, and `/v1/agents` names the version served so
Elixir drafts the next one on it. A new carry-over starts the chain again at v0: the kept versions
follow the older configuration and are set aside.

**Still to build.**

- **Portal:** keep the versions and serve them to the gateway (`GET` with the hand token); show a
  draft as the difference in words before it is signed, and keep those words in the version.
- **Elixir:** draft the next version from Portal's grants on the version the gateway names; sign a
  narrowing itself; leave a widening for the owner.
- **hand.mjs:** `policy sign`, on the token, showing the change in words before the touch (and,
  later, the phone app over NFC, so widening needs no laptop either).
- **The carried configuration:** `policy_log` with the URL and the keys, carried over once.
- **The conformance statement:** the disclosed gap on a lagging grant closes; the passkey row and
  the grant rows change.

**The passkey inside a working set: still open.** The working set names Portal projects; the
gateway knows repositories. Which repository belongs to which project is Portal's own data, so a
widening approved by passkey and bounded by the set would still rest on Portal for that mapping.
Until that is settled, a widening is signed on the token. The owner's token over NFC on the
phone is the way to make that a tap anywhere.

## Ending a word early, as built (7 October 2026)

A capability is a signed token the gateway checks on its own, so ending an admission at Portal
used to stop only new tokens: one the hand held stood until its expiry, up to the end of a
working set. Now the gateway reads Portal's list of capabilities ended before they expired
(`revocations.url` in the carried configuration, `GET` with the gateway's Portal token, every 30
seconds, in memory, `cmd/gateway/revoked.go`) and refuses an action under one, with the moment it
was ended in the record. The list only takes away, so it needs no signature: a Portal that lies
in it can stop work, which it already can by issuing nothing. A read that fails keeps the last
list; an entry leaves only at the capability's own expiry. Between the end at Portal and the
next read, at most 30 seconds, the token still acts.

## Open questions

1. **The strong key on a phone.** Can the YubiKey sign the working set over NFC from the phone
   (WebAuthn with the YubiKey as a security key), so declaring a set needs no laptop either?
   Then the strong key is a tap of the token on the phone.
2. **How long a set may stand.** A week fits the way the owner plans; a hard maximum keeps a
   forgotten set from standing for months.
3. **B3 inside a set.** A per-action signature by passkey inside a set, or the strong key for every
   B3 action regardless? The first is smoother; the second keeps every irreversible act at the token.
4. **Revocation.** Ending a set early must take one tap and reach the gateway and the systems
   before the next action.
