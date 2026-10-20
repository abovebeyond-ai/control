# Identity: the company's directory and DIDs

Two additions to the Odoo gate, in this order. Neither is built yet; this note says what each
one changes, what stays as it is, and the order to build them in.

## What exists

- Acme's registry is a chain of signed `re1` entries (`registry/registry.go:36`): the root signs
  a director, the director signs a buyer. Each entry carries a role, kinds, a ceiling per order,
  a daily allowance and an expiry. The gate checks the whole chain on every word
  (`VerifyChain`, `Revoked`, `gateway.orgWord`), and a revoked entry anywhere in the chain stops
  every word below it.
- The signing keys live in `acme-admin` (gate-demo-box), the entries at the Bextrust relay,
  which checks their shape but holds no key and verifies no signature.
- The agent's entry already names a DID: `did:web:<domain>:acme#procurement-agent`
  (gate-demo-box `acme-admin/agent.go`). Nothing serves a document for it.
- The gateway can read DID documents (`relying.DocumentURL`, `relying.ResolveKeys`) and a
  did:webvh log (`anchor/identity.go`), and anchors identity versions (`PinIdentity`). It does
  not verify did:webvh entry hashes or proofs.
- Nothing reads a company directory (Entra, Okta, Google Workspace). The console's names come
  from a fixed `CONSOLE_PEOPLE` string.

## One limit both additions keep

The directory says who holds which role. It never signs. A word to the gate stays a passkey
signature by the person, checked against the person's entry. If a directory login could
approve, a directory admin could approve in anyone's name, which is the weakness of an ERP log
the demo's first scenario shows.

## 1. The company's directory

**What it does.** A sync in `acme-admin` reads the directory and keeps the registry in line
with it:

- A mapping, kept by Acme, from directory groups to registry roles:
  `"Purchasing" -> buyer, kinds [odoo.purchase], ceiling 2500, daily 10000`,
  `"Directors" -> director, may delegate`. The mapping is itself signed by the root, so the
  sync cannot widen a role on its own.
- A person in a mapped group with no entry gets an invite. Enrolment still needs the person's
  passkey on their phone; the sync cannot create one.
- A person who leaves the group, or whose account is disabled, gets a revocation (`rv1`)
  signed by the entry's signer. The gate refuses the chain from then on.
- A person whose group changes gets a new entry and the old one ends (re-enrol already ends
  the old mandates, `endMandatesOf`).
- Each entry records the directory's id for the person (`sub`), so a receipt names the same
  person the company's own systems know.

**Changes.**
- `registry.Entry` gains `Sub string \`json:"sub,omitempty"\`` in both repos (control-odoo
  parses with `DisallowUnknownFields`, so the gate must learn the field first).
- `acme-admin sync --directory <adapter> --map <signed mapping>`, printing what it would do
  before it does it (`--apply`).
- Adapters: first a directory snapshot file (JSON: users, groups, enabled), which is what the
  demo runs on; then Microsoft Graph (groups, members, `accountEnabled`). Okta and Google
  Workspace follow the same shape. An adapter is not called working until it has run against a
  real tenant.
- The relay ends only mandates whose leaf entry is revoked. The gate already refuses the rest;
  the relay should end them too, so the phone shows them as ended.
- The console reads names and departments from the relay's names registry instead of
  `CONSOLE_PEOPLE`.

## 2. DIDs for Acme and its agents

**What it does.** Acme's root key, its gate key and its agents are published in a DID
document, so an auditor or a supplier checks a signature against Acme's own published keys
instead of a key someone handed them.

- `did:web:<domain>:acme` resolves to `https://<domain>/acme/did.json`, with verification
  methods `#root`, `#gate` and one per admitted agent (`#procurement-agent`, matching the DID
  the agent entry already carries).
- `acme-admin did` writes the document from the root and the signed entries; Acme's edge serves
  it. Bextrust's relay does not serve it: a document Bextrust serves is a document Bextrust
  could change.
- The console and the verifier resolve the document and compare it with the root they pin.
  A mismatch is reported, never silently accepted. The gate keeps its pinned root in its
  configuration and checks the document against it at start.

**Then did:webvh.** did:web trusts whoever controls the web server. did:webvh adds a log where
every version is signed by the previous key, so a rotated or replaced root shows in the history.
This needs entry hash and proof verification in `anchor/identity.go`, and then reuses
`PinIdentity` to anchor each version on ISBE.

## Order of work

1. `Sub` and the `did` field in control-odoo's `registry.Entry`, with tests (the agent entry's
   `did` field is refused by control-odoo's parser today).
2. Acme's DID document: `acme-admin did`, the edge route, the console and verifier check.
3. The directory sync on a snapshot file, with revocation and the relay ending descendant
   mandates; a demo moment where offboarding Elise stops her agent's next write.
4. The Microsoft Graph adapter, tested against a tenant.
5. did:webvh proofs and anchoring of Acme's DID versions.
