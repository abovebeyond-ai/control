# An agent in a client's Odoo, on a person's word

Built on 17 October 2026 for the Bextrust gate demo, on a branch, not released. An AI
procurement agent works in Acme's Odoo 19 through this gateway. Odoo's API stays as it is: the
gateway holds the Odoo API key and is the only thing that calls Odoo. The agent reads under a
mandate a buyer signed with a passkey; every write needs the buyer's passkey on that exact
action; and what cannot be called back (approving or sending an order, paying a bill) has no
kind at all. The authority does not come from us: it comes down a chain of registry entries
from Acme's own root key, which the gateway pins.

The contract between the gate, the relay and the app is `docs/contract.md` in the demo's box
repository. This note says what the gate side does with it.

## Who speaks: the registry chain

Acme's root key (Ed25519) signs an entry for Tom, the purchasing director; Tom's key signs an
entry for Elise, the buyer, whose key is a passkey on her phone (P-256). An entry is a `re1`
token (`registry` package): the entry as canonical JSON, signed by the parent.

| field | what |
| --- | --- |
| `id`, `org`, `parent` | `acme#elise`, `acme`, `acme#tom` (the org itself for an entry the root signs) |
| `holder` | the child's public key as a JWK: OKP/Ed25519 to sign entries, EC/P-256 for a passkey |
| `credential_id` | the passkey's id, for the relay; the gate checks the key, not the id |
| `role`, `kinds`, `ceiling_eur`, `may_delegate`, `iat`, `exp` | what the holder may do, up to which order total in whole euros, until when |
| `daily_eur` (optional) | the most the orders under the holder's word may add up to in one day (Europe/Brussels), in whole euros |

The gateway holds a chain, root first, to these rules (`registry.VerifyChain`):

- the first entry names the org as its parent and is signed by the root key pinned for that
  org in the configuration (`orgs`); each later one names the entry before it and is signed by
  that entry's Ed25519 key;
- only a parent with `may_delegate` signs children, so a passkey holder signs none;
- a child's kinds are a subset of its parent's, its ceiling and its end no higher;
- under a parent with a `daily_eur`, a child has one too, no higher; a parent without one puts no bound;
- every entry is in date, its id lies under its org, no entry appears twice, at most eight;
- the payload bytes are canonical JSON and carry no field the contract does not name, so the
  bytes Acme signed have one reading.

## The word: a passkey capability

The passkey signs control's capability payload (`capability.Payload`) unchanged. The token is
`wa1.<payload>.<authenticatorData>.<clientDataJSON>.<signature>`, each part base64url, and
`capability.VerifyPasskey` holds it to:

- the challenge in clientDataJSON is base64url(SHA-256(payload bytes)), so the signature covers
  the payload and nothing the relay could change; the type is `webauthn.get`; the origin is one
  the configuration lists (the site and the app's `android:apk-key-hash:...`); not cross-origin;
- authenticatorData's RP ID hash is SHA-256 of the configured RP ID, with user presence (UP)
  and user verification (UV) both set;
- the ES256 signature over authenticatorData || SHA-256(clientDataJSON) verifies under the
  holder key of the entry the chain ends at, and the payload's `iss` is that entry's id;
- then what every capability is held to: this gateway (`aud`), this agent (`sub`), in date.

After that the existing semantics apply as they are (`gateway.heldWord`): an early end through
the revocation list, `Covers` for kind and resource, the task, and for a word per act the act
digest (`capability.ActDigest`) and the spend of its `jti`. The registry entry must give the
kind as well.

## The grant

A grant that names `org` listens to that organisation's people and to nothing else: every
capability must be a `wa1` word with a chain to the pinned root. A B1 kind (`odoo.read`) runs
under a mandate, a word that names a period. Every other kind needs a word that names the act,
whatever `per_action` says, so a mandate that lists a write kind still carries no write.
`asks` names the entry asked for a word when the agent names nobody.

```json
{
  "issuer": "https://bextrust.abovebeyond.ai/control",
  "orgs": {"acme": "<hex Ed25519 root key>"},
  "passkey": {"rp_id": "bextrust.abovebeyond.ai",
              "origins": ["https://bextrust.abovebeyond.ai", "android:apk-key-hash:<b64url sha256>"]},
  "relay_url": "https://bextrust.abovebeyond.ai",
  "odoo": {"acme": {"base": "https://acme.odoo.example", "db": "acme", "currency": "EUR"}},
  "agents": {
    "did:web:bextrust.abovebeyond.ai:acme#procurement-agent": {
      "grant": {"principal": "acme", "org": "acme", "asks": "acme#elise",
                "kinds": ["odoo.read", "odoo.order_draft", "odoo.order_line_set", "odoo.order_cancel", "odoo.order_request_approval"],
                "resources": ["odoo:acme/*"]}
    }
  }
}
```

The Odoo API key is `odoo-key-acme` in the secrets directory. A grant that names an org whose
root is not pinned, or no RP ID and origins, stops the gateway at start. The bundle a record
names carries `org`, and a policy version that changes it is a widening.

## The kinds

The resource is `odoo:<instance>/<model>`. The judgement refuses a model outside
`policy.OdooModels` (`purchase.order`, `purchase.order.line`, `res.partner`,
`product.product`, `product.template`, `stock.quant`) before anyone is asked.

| kind | radius | params | what the adapter does |
| --- | --- | --- | --- |
| `odoo.read` | B1 | `model` (the resource's), `domain`, `fields`, `limit` (1 to 200) | `search_read`; plain field names only, no path into another model; a domain of plain terms and comparison operators; a default field list without binaries |
| `odoo.order_draft` | B2 | `partner_id`, `lines` [{`product_id`, `qty`}] | prices the lines at the products' `standard_price` and refuses above the ceiling before creating; creates the order in draft; holds Odoo's own `amount_total` to the ceiling and cancels the draft at once when it is over |
| `odoo.order_line_set` | B2 | `order`, `line`, `qty` | only on a draft and a line of that order; estimates the new total at the line's price, refuses above the ceiling; writes; sets the old quantity back when Odoo's total is over |
| `odoo.order_cancel` | B2 | `order` | `button_cancel`, only on a draft or an order waiting for approval |
| `odoo.order_request_approval` | B2 | `order` | `button_confirm`, after checking it cannot approve: the company approves in two steps, the total is at or above the threshold, the gateway's Odoo user is no purchase manager; the state after must be `to approve` |

Ids and quantities are whole numbers above zero: the record's canonical form has no fractional
numbers, so amounts in an outcome are strings with two decimals. The ceiling is the gateway's
addition from the verified entry (`ceiling_eur`), never the hand's, and it is compared with the
order's `amount_total` (taxes included) in the instance's currency; an order in another
currency is refused. A write that arrives at the adapter without a ceiling is refused.

When the signer's entry has a `daily_eur`, the gateway also hands the adapter what the signer's
orders came to today (`spent_today_cents`, from `allowance.jsonl` in its store) and holds the
read, the check and the add under one lock. A draft counts with its `amount_total`, a quantity
change with how much the total moved (going down counts back); a cancel or a request for approval
adds nothing. What would take the day over is refused the way the ceiling is: at cost before
creating, and cancelled or set back when Odoo's own total goes over ("over acme#shane's daily
allowance: EUR 6519.00 of 5000.00 would be used"). The effect's detail carries `daily_eur` and
`spent_today_eur` after the act.

## Waiting for a word

A write that needs a word and comes without one is judged against the grant first, without a
record, so nobody is asked to sign what the grant refuses. Then `/v1/submit` answers 202:

```json
{"pending": "<id>", "holder": "acme#elise", "payload": "<b64url>", "challenge": "<b64url>", "action": {"kind": "...", "resource": "...", "params": {...}}}
```

The payload is a capability for that one act: `iss` the holder, `sub` the agent, `kinds` and
`resources` the action's, `act` its digest, `jti` `word-<id>`, ten minutes long. The same object
is posted to `RELAY_URL/api/requests` (`relay_url`, or the environment); nothing is announced
when neither is set.

| method | who | what |
| --- | --- | --- |
| `POST /v1/pending/{id}/word` | client, relay | `{capability, chain}`: judged like any submission; performed when it holds; the answer is what the relay is told: `{verdict, reason, step, action}` |
| `POST /v1/pending/{id}/refuse` | client, relay | `{by}`: a refusal on the record ("refused by acme#elise"); nothing performed; answered as a word |
| `POST /v1/pending/{id}/adjust` | client, relay | below, under the view and adjusting |
| `GET /v1/pending/{id}` | client | `{state: waiting, done, refused or expired, record}` |
| `GET /v1/pending/{id}` | relay | `{state}`, or `{state: "replaced", by}`: no params, record, effect or amount |

The client token (`client_token`, `client_token_sha256`, `CLIENT_TOKEN_SHA256`) is the agent's.
The relay has a token of its own (`relay_client_token_sha256`, `RELAY_CLIENT_TOKEN_SHA256`; not
`relay_token`, which the gate presents to the relay), and the gate refuses to start when the two
are the same. The relay's token cannot submit. A word that does not hold is a refusal on the
record and decides the write (`done`, with a DENY); the agent asks again. A write whose ten
minutes pass is recorded as refused when it is next asked for or swept (every minute). A decided
write answers 409 to a second word, refusal or adjustment, with `{state, record}` where the record
is what the relay is told, never the whole record.

**Who reads the records.** `GET /v1/records`, `/v1/attachment`, `/v1/proof` and `/v1/policy` carry
record bodies, params, outcomes, amounts and reasons. Once `readers` names a reader, and always in
Confidential Space, they are served only to a bearer token whose SHA-256 is one of
`"readers": {"<name>": "<hex sha-256>"}`; every read, served or refused, is on the access record,
the served ones with the reader's name. Readers come from the baked configuration only, never
from the environment, which the operator sets in Confidential Space; a reader whose token is the
client token is refused at start. Open to anyone, for an anchor and for provisioning:
`/v1/key`, `/v1/attestation` (and `?digest=`), `/v1/attestations`, `/v1/agents`,
`/v1/checkpoint`, `/v1/checkpoints`, `/v1/consistency`, `/v1/provision-key` and
`POST /v1/provision` (signed by the organisation).

## What is recorded

Every outcome, the word, the refusal and the expiry, is three records like any action: the
request, the effect, the result. A request under a word names the person as `initiating_user`
(`acme#elise`), the word in `control_capability` and `control_task`, the chain in
`control_chain` (ids, digest, role and ceiling of the entry that spoke, and its `daily_eur` with
`spent_today_eur` as the day stood before the act when it has one), and a spent word in
`control_word`. The word and its chain are kept beside the record (`capability` attachment), so
a stranger can replay both against Acme's root key. A refusal by the person carries
`control_refused` with who the relay says refused.

The rows a read returns go back to the agent and stay off the record: the outcome on the
record carries their count and the SHA-256 of Odoo's answer (`records_sha256`), since the
attachment endpoint is open to anyone who reaches the gateway. The answer the agent receives
therefore carries more than the answer the result record digests.

## Sealed receipts

Under a grant that names an organisation, every action ends with a receipt for the person it was
taken in the name of: the word's or the mandate's signer, else the person the grant asks
(`asks`). The plaintext (canonical JSON) names the action, the verdict and reason, whether that
person's word was asked, the effect's detail, the chain with ceiling, daily allowance and the day
after the act, the action's signed records as stored, and the gateway's record key (`gate_key`).

It is sealed with HPKE (RFC 9180: base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM, info `bextrust receipt v1`, aad the canonical JSON of `{holder, id, at, kid}`) to the
`enc` key in the person's registry entry, which the parent's signature covers, and a second time
to the configuration's `audit_enc` under `<org>#audit`. The key comes from the chain the gateway
verified for the act; without one (a refusal before any word) the gateway fetches the person's
chain from the relay and verifies it from the pinned root, so a relay cannot slip in a key of its
own. A person without `enc` gets no envelope, and that is logged.

**Who receives it.** Besides the person and the audit key: every entry above the person on
their chain that may delegate and has an `enc` (their managers), in full; and every observer
whose view covers the person. An observer is an entry with role `observer`, no kinds, an `enc`,
and `sees: {under, detail, partners, until}`. It covers a person when `under` is the organisation
or an entry on the person's chain, and the entry that signed the observer stands at or above
`under` on that chain (`registry.Covers`): nobody attaches an observer to a part of the
organisation outside their own, and only the root gives a view of all of it. With `partners`,
only the actions on those Odoo partners' orders reach it. The gateway reads the observer chains
from the relay (`GET {relay_url}/api/registry?org=<org>&role=observer`), verifies each from the
pinned root, and keeps the list for a minute.

**Summary detail** carries the kind, verdict, a reason class (within grant, refused, over limit,
expired, failed), the order total, state and currency, the limits used, who and when, and the
inclusion proof with each step's snapshot digest and verdict: no parameters, records, product
or partner names, prices or reasons in words. **Full detail** adds the parameters, the effect,
the records, the outcome as recorded, the agent's `reasoning` when it gave one, and the passkey
word with its chain.

**Proof without the anchor holding records.** Each receipt carries the proof of the action's
records into the signed checkpoint at the action's end (`inclusion`). The gateway serves those
checkpoints (`GET /v1/checkpoints?agent=&after=N`, one per action end plus the current one) and
consistency proofs between them (`GET /v1/consistency?agent=&m=&n=`), so the anchor anchors
every checkpoint a receipt can name and holds the gate to an append-only log, with nothing but
hashes. A reader asks the anchor which minute holds the checkpoint's root.

**Gaps.** Every plaintext names its `recipient`, a `seq` (the number of envelopes the gateway
sealed to that recipient, ever) and `day`/`day_count`, and the gateway signs it (`sig`, Ed25519
by the record key over the canonical plaintext without `sig`). HPKE base mode does not say who
sealed; the signature does. A recipient whose `seq` jumps knows a receipt did not reach them,
and the relay cannot fill the gap. The counts are `outbox/seq.json` in the store.

`receipts.go` keeps this off the request path: settle writes a job to `outbox/` in the store, a
worker seals one envelope per key and posts it to `{relay_url}/api/receipts`, and what the relay
does not take waits there for the next round (every minute). A receipt never changes a verdict.
The relay stores ciphertext; what it still sees is who gets a receipt, when, and how large.

## Sealed requests

When a write waits for a person's word, the gateway reads from Odoo, with the instance key and
only reading, what the person needs to decide (`effects.Odoo.Display`): for a draft the supplier's
name and each product's name, code, quantity, unit and cost with the total at cost, the
supplier's last price per line (its `product.supplierinfo` entry for that quantity, else the last
confirmed order line, left out when Odoo has neither or does not answer) and the date Odoo will
plan the order for when the supplier has a lead time; for a quantity change, cancel or approval
request the whole order as Odoo has it (name, state, supplier, currency, `date_order`,
`date_planned`, every line with code, quantity, unit, unit price and subtotal, and the untaxed
amount, tax and total), a person approving an order and not a step. It seals
`{v, pending, holder, exp, agent, action, act, display, reason, reasoning, payload_digest, gate_key,
recipient, sig}` (HPKE as receipts, info `bextrust request v1`, aad the canonical JSON of
`{holder, pending, exp, kid}`) to the person's current entry's `enc` (their chain at the relay,
verified and not revoked) and to `audit_enc`, signs it with the record key, and tells the relay
only `{pending, holder, exp, payload, challenge, sealed}`: no action, no names. `act` is
`capability.ActDigest(action)`, the digest the payload names, so the phone can hold the screen to
what the passkey signs. `reason` is the agent's own words, sent with the submission
(`reason` in the body, outside the act digest, inside what the agent signed). `reasoning` travels
the same way: a list in the body of at most eight sentences of what the agent read and why it
chose this supplier, quantity and step, each trimmed and cut at 300 characters, anything else in
its place left out; it is sealed into the request and into the receipt of the step. The relay hears
only the verdict, reason, step and action id of a decided write; the agent reads the whole
record from the gateway (`GET /v1/pending/{id}`).

**The view and adjusting.** Beside `display` the sealed request carries `view`, which any app
draws without knowing the kind: `title`, `fields` [{label, value}], `table` {columns, rows},
`totals` [{label, value}] and `adjust` [{path, label, value, min, max, step}], all text the gate
wrote from the display. A draft offers each line's quantity (`lines.<i>.qty`), from 1 to what
keeps the total at cost within the holder's ceiling and what is left of their day; a quantity
change offers `qty` within the same bounds on the estimated total and the day's increase; cancel,
approval and read offer nothing. Without the holder's entry no bound is known and nothing is
offered. `POST /v1/pending/{id}/adjust {"holder","changes":[{"path","value"}]}` (the relay's
token) checks each change against what was offered, makes the changed act a new waiting
word (new payload, challenge and sealed request; the agent's submission and reasoning as they
were, plus a line saying who changed what from what to what) and marks the old one `replaced`.
It answers `{"state":"replaced","replaced":<old>,"by":<new>,"pending":<new>}` and nothing more:
the relay carries the answer, and the new payload, challenge, labels and values reach it and the
phone in the announcement of the new word, which names `replaces`. A change the gate does not take
is answered `{"error","code"}` with a generic text per code (`not_holder`, `not_adjustable`,
`outside_view`, `nothing_changed`, `grant`, `busy`), naming no line, label, value or bound; the
detail goes into `sealed`, one envelope for the holder's key (as a sealed request, HPKE info
`"bextrust adjust refusal v1"`, aad canonical `{"holder","pending","kid"}`, plaintext
`{"v","pending","holder","recipient","code","detail","sig"}`, `sig` the gate key over the
canonical plaintext without `sig`), when the holder's entry has one. `GET /v1/pending/{old}` answers
`{"state":"replaced","by":<new>}`, and a word on it 409 with the same. The request record of the
new word carries `control_adjusted` {from_pending, by, changes [{path, label, from, to}]}, from
the gate and never from a submission; the receipt carries it as `adjusted`.

**A re-enrolled person's old passkey.** The revocation list may carry `entries`, signed
revocations (`rv1`) of registry entries by the digest of their exact text, signed by whoever
signed the entry. A chain with a revoked entry is refused (`registry.Revoked`); a revocation
signed by anyone else is ignored, so whoever serves the list can withhold one, never invent one.

## Durable state

The organisation provisions, beside the Odoo keys, a `state-key` (32 bytes, as 64 hex
characters or base64). With it the gate keeps its waiting words (each with the submission as
the agent signed it, reason and reasoning included, the payload, and the announcement) and its
receipts outbox (jobs, envelopes, and each recipient's `seq` and `day_count`) in one blob,
AES-256-GCM under that key, `aad` = `"bextrust gate state v1"` followed by the seq as 8 bytes
big endian, and puts it at the relay after every change, a burst of changes making one blob:
`PUT {relay_url}/api/gate/state {"v":1,"seq","at","nonce","ct"}` (nonce and ct base64url), with
the relay token. Once it holds the key and before it stores anything, it reads the latest
(`GET /api/gate/state`, 404 when there is none), drops the words whose ten minutes passed and the
decided ones older than an hour, announces the waiting ones again, and delivers the outbox; the
counts never go down. A relay that answers 409 to a PUT holds a later seq; the gate goes on from
there. Announcements and receipts are posted again with backoff (1 s doubling to 60 s) until the
relay takes them; nothing is dropped for waiting. Without a state key the gate says so and
keeps everything in memory, as before.

An older blob cannot make a write happen twice. A word's write carries the pending id to the
adapter (`bextrust_pending`, added after the judgement, like the ceiling): a draft goes to Odoo
with `origin` = `bextrust:<pending>`, and before creating one the adapter looks for that origin
and answers with the order it finds (`already: true`, not counted against the day again). A
request for approval of an order already waiting for approval, a cancel of a cancelled order and
a quantity already set are answered the same way, without a write.

## Not built

- **Ending a mandate early.** The relay's `/api/mandates/{id}/end` and `/api/stop-all` are not
  seen by the gate. The gateway's revocation list (`revocations`) could read a list the relay
  serves in Portal's format; until it does, a mandate ends at its `exp`.
- **Revoking a registry entry** before its `exp`. A chain holds until its first entry ends.
- **The passkey's signature counter** is not tracked; phone passkeys mostly send zero.
- **Waiting writes survive no restart without a state key**: they then live in memory only
  (see *Durable state*). Nothing was judged for them; the agent asks again.
- **A restored receipt job** that the earlier gate had not sealed yet is signed by the new
  gate's key, while its records and `gate_key` are the earlier gate's; the phone then shows it
  as failed. Jobs are sealed at once, so this needs the relay to be away when the chain is asked
  for, and the gate to restart before it is back.
- **One gate.** Two gates storing one state would need a lease in the blob.
- **A refusal is not signed.** Refusing only keeps something from happening, so the relay's
  word is taken; the record says it is the relay's.
- **Currency conversion.** The ceiling is in euros and compared with an order in the instance's
  currency. The local demo database runs in USD; set the Odoo company's currency to EUR, or
  `currency: "USD"` for that instance and read the ceiling as dollars.
- **Odoo state between check and call.** The adapter reads an order's state and total and then
  acts; a person changing the order in Odoo in between is not excluded.
- **Fractional quantities** have no kind, for the canonical form's sake.
- **Per-task grants** do not combine with an org: the word names no playbook.
- **No enforcement at Odoo's end.** Odoo does not see the record; the gateway's API user is the
  only holder of the key, and its Odoo rights (purchase user, not manager) are the far end's
  bound.

The tests: `registry` (chain and narrowing), `capability` (the passkey word), `policy` (the
Odoo rule and the two schema types), `effects` (the adapter against a fake Odoo that applies
Odoo's approval rule), `cmd/gateway` (the whole demo with a fake Odoo and relay). With
`CONTROL_ODOO_IT=1`, `effects` also runs against the Odoo at `http://127.0.0.1:8069` (database
`acme`, key in `/home/bench/work/odoo-demo/gate.key`): it reads every model, drafts an order,
changes a quantity, asks for approval and cancels it.

## One Odoo user per agent

Every agent behind the gate can have its own Odoo user, so Odoo itself shows which agent did
what: Acme creates a user per agent (same narrow rights as the instance user: Purchase/User under
two-step approval) and gives the gateway its API key as `odoo-key-<instance>-<agent>`, where
`<agent>` is the fragment of the agent's identifier (`procurement-agent` for
`did:web:...:acme#procurement-agent`). The gateway adds the agent's name to the action it performs
(`odoo_agent`, its own addition, never the hand's); an agent without its own key goes as the
instance's user. Disabling an agent's user in Odoo stops that agent at Odoo too, whatever the gate
does. People are never Odoo users of the gate: who allowed a write is in the record, and the
irreversible steps happen in Odoo under each person's own login.

## In Google Confidential Space

Added on 17 October 2026, late: the gateway runs in Google Confidential Space on Intel TDX
(`attestation: "confidential-space"`). The demo's `docs/contract.md` (The gate in Confidential
Space) has the deployment; this is what the gateway does.

Why not the plain TDX VM this repository's `deploy/gcp` runs: there the startup script is not
measured, so whoever operates the VM could change what runs, and read the gateway's memory,
without the quote changing. In Confidential Space the operator chooses the container image and
nothing else; Google's launcher, boot chain and kernel are measured, there is no SSH, and Google
Cloud Attestation signs a token naming the image digest. The image holds the binary and the
configuration, so the digest covers the policy too.

- **The key and the token** (`cmd/gateway/cs.go`). The record key is made in memory at start
  and never written; each key writes its own log directory. The launcher (`POST /v1/token` on
  `/run/container_launcher/teeserver.sock`, `token_type` OIDC, `audience` the issuer) gives a
  token whose `eat_nonce` is the hex SHA-256 of the record key (`attest.KeyNonce`); a new one
  every day, each kept by its digest. Records carry `submods.attestation` = platform
  `GCP_INTEL_TDX`, software `CONFIDENTIAL_SPACE`, measurement `sha-256:<image digest>`,
  `image_digest`, and `token` (the digest of the token in force); checkpoints carry the token's
  digest under their signature.
- **Checking it** (`attest.VerifyCS`, used by `attest.Verify` and `cmd/verify --expect-digest`):
  RS256 under Google's keys from the OIDC discovery document at
  `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`; `iss` that
  host; `hwmodel` `GCP_INTEL_TDX`; `swname` `CONFIDENTIAL_SPACE`; `dbgstat`
  `disabled-since-boot`; `submods.container.image_digest` the expected digest; `eat_nonce` (string
  or array) containing the key's nonce. Claim names as Google documents them
  (confidential-space/docs/reference/token-claims), and as the first live token showed.
- **Nothing secret in the environment.** The launcher copies the container's environment into the
  token (`submods.container.env`), which is public. So the client token comes as its SHA-256
  (`client_token_sha256`, `CLIENT_TOKEN_SHA256`), and the gateway refuses to start in this mode
  with a client token in the clear. (Found on the first deploy, which passed the tokens
  themselves; they were replaced.)
- **Attested provisioning** (`cmd/gateway/provision.go`). `GET /v1/provision-key` answers a P-256
  key made in memory, signed by the record key; `POST /v1/provision` takes an HPKE envelope (the
  receipts' suite, `info` "bextrust provision v1") of named files, signed by the org's pinned root
  (`odoo-key-*` only) or by a configured provisioner (`provisioners`, its key and its files: the
  relay's operator with `relay-token`). The files stay in memory; the Odoo adapter reads them
  first and, in this mode, nothing else (`effects.Odoo.OnlyProvisioned`); until they come the
  gateway answers Odoo work with 503 and the plain reason. Each provisioning writes one record,
  `control_event: "provision"` with no action id, naming the files, the key sealed to, the signer
  and the envelope's digest, never a secret.
- **The relay's door.** `relay_token` (or the provisioned `relay-token`) goes as a bearer token on
  every relay call: requests, receipts, chains, observers, revocations.
- **Receipt ids** name the log: `<agent>/<first 16 hex of the record key>/<last step>`, since a
  new key starts at step 0 and the relay and the phone keep the first receipt of an id.

What a restart costs: a new key, an empty log, the daily allowance's sum and the receipts'
sequence numbers start again, waiting writes are gone, and the organisation must provision
again and sign its gate entry for the new key. The anchor follows the new key on Google's word.
