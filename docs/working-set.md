# The working set: one strong word, then a passkey wherever you are

Status: designed on 6 October 2026, largely built by 9 October. The owner signs a working set on
the token (`hand.mjs workingset`, or the phone over NFC), Portal keeps it and admits every project
in it until its end with one passkey touch, and it can be ended in one tap. The gateway reads a
signed policy log, a repair widening goes through on a passkey, and capabilities ended early are
refused. What is not built: the gateway and the systems do not check a working set themselves (it
bounds what Portal admits, not what the gateway accepts), and a passkey widening is bounded by the
repair rule, not by the set. The sections marked *as built* say exactly what runs; the ones before
them are the design they came from. It builds on `mandates.md` (commands modelled on blast radius)
and changes how the owner approves, not what a hand may do.

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
may sign any version. `repair` keys (Portal, after the owner's passkey) may sign a version
that adds only reversible kinds and resources (see *A widening by passkey*). `narrow` keys (Elixir) may sign a version only if the gateway itself finds
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

**Built since** (checked 9 October 2026): Portal keeps the versions and serves them to the
gateway (`/api/control/policy`) and shows a draft in words before it is signed; Elixir drafts the
next version on the one the gateway names, signs a narrowing itself and leaves a widening for the
owner (`App\Control\PolicyLog`); `hand.mjs policy sign` signs on the token, and the phone app does
the same over NFC; Elixir writes `policy_log` into the configuration it carries; the conformance
statement describes grants changing through policy versions.

**The passkey inside a working set: still open.** The working set names Portal projects; the
gateway knows repositories. Which repository belongs to which project is Portal's own data, so a
widening approved by passkey and bounded by the set would still rest on Portal for that mapping.
Until that is settled, a widening is signed on the token. The owner's token over NFC on the
phone is the way to make that a tap anywhere.

## A widening by passkey, as built (8 October 2026)

A widening that only adds what is undone in one step no longer needs the token. A third signer
role sits beside `widen` and `narrow` in `policy_log.signers`: `repair`, Portal's key
(`did:…#portal`, the Google KMS key that already signs capabilities). The gateway accepts a
version from a repair key only when, against the version served, it adds nothing but

- kinds from `policy.RepairKinds` (`policy/repair.go`), each with its radius named: the
  workbench's proposal kinds (`branch.push`, `pull.open`, `issue.open`, `preview.push`,
  `forge.deploy`), the `portal.*` writes, and the B2 system kinds (`stocklist.photos_repair`,
  `studio.research_draft`, `observatory.trend_edit`, `observatory.trend_site`), to a hand or to
  one of its tasks;
- resources, for a hand that already exists and whose every kind is on that list (a new
  resource reaches every kind the hand holds, so a hand holding `review.invite` or
  `workflow.dispatch` gets a new repository only on the token);

and changes nothing else: no new hand, task, system or system address, nothing about who speaks
for a hand, no higher count, no certificate or per-action word dropped, no judgement accepted.
The rest is `Narrower`'s check, run on the version with the allowed additions taken off. What
reaches a person or cannot be called back (`review.invite`, `review.sign`, `pull.merge`,
`pull.ready`, anything B3) is not on the list; a test keeps every system kind decided for it.

Elixir marks a draft `repairOnly` by the same rule, ported line for line, and only when the
running gateway names Portal's key among its repair signers (`/v1/policy` serves them): before the
carry-over the gateway would refuse Portal's signature, and a refused version blocks every later
one. Elixir writes Portal's key under `signers.repair` in the configuration it drafts. Portal shows such a draft on the
Grants page with an approve button; on the passkey touch it signs the version with `#portal`,
keeps the assertion's hash beside it, and keeps the version like any other. Portal refuses a
`#portal` version for a draft that is not `repairOnly`, and the gateway refuses it again on its
own. The gateway learns the repair signer only from a carried configuration, so the role takes
effect after a release and one carry-over.

Not yet: the approval is bounded by the rule, not by a working set. A passkey approval that must
fall inside the owner's working set (its projects, its layer, its end) is the next step.

## The owner's key on the phone, as built (7 and 8 October 2026)

Everything the token signs at the laptop can now be signed on the phone, with the same YubiKey
held to its back over NFC (portal-android `docs/yubikey.md`, Portal `SignOnKey`): a working set,
a widening of the policy, and an admission of one workbench on one project, reading for 30 days
included. The bytes are the same RFC 8785 form under the same operator key, so the gateway checks
them as it checks the laptop's and needed no change: an admission names its operator issuer, which
`principal_keys` already verifies, and the workbench carries the key's own signature, not one
Portal made.

PIV signs whatever bytes it is given and binds no origin, unlike a passkey. Two checks take that
place. The app holds Portal's offer against what the owner chose before the PIN is asked (the
projects, hand, layer and end; a read word names read verbs on running systems only; the audience
is the gateway under the app's own Portal), so a Portal that was broken into cannot put a wider
word under a narrow sentence. Portal keeps a token only when it is its offer exactly plus an
operator issuer, once, for the session that asked. The PIN and the tap are the step-up on every
signature. Without NFC or without the key, the passkey and the laptop remain.

Not yet: PIV attestation of slot 9c published beside each operator key, so the gateway itself can
tell that the slot demands a touch (today the app reads it off the key and refuses a slot that does
not); and a run on a real phone with a real key.

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
