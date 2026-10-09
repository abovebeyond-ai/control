# Facts and crosswalks: how this system meets a standard that moves

A draft note, 9 October 2026. Nothing here replaces `conformance/statement.md` or
`conformance/register.json` yet.

## The problem

The statement and the register were written against Proof-of-Control draft v0.1: claims
keyed to its chapters (C4, C7, C8) and rows (4.1.1, 8.1.5), with a tier written by hand
next to each. The standard has since become a Working Draft v1.0 with six named domains, no
row ids, and a stricter reading of the tiers. Every citation in the statement now points at
text the standard no longer has, and the tiers were never derived from anything a reader
can recompute.

## Two layers

**Facts** (`conformance/facts.json`) say what the system does, in its own words, under ids
it owns: `judged-before-effect`, `history-anchored`, `revocable`. Each fact names its
mechanism, the code and documents that are its evidence, a command that checks it, whether
it is live or designed, and the parties it asks a reader to trust. Each party has a kind:
`hardware-vendor-attestation`, `timestamp-authority`, `operator-service-key`. A fact
changes when the system changes.

**Standards** (`conformance/standards/<id>.json`) say, for one version of one standard,
where each fact lands (domain, rows if the version has them) and how far each kind of
party lets a fact rise, with the standard's own words as the reason. A standard file
changes when the standard does, and a new version is a new file beside the old one.

The tier is computed: the lowest cap among the parties a fact trusts. A set of independent
parties (DigiCert and Hedera for the anchors) counts as one party only where the standard
says a threshold of independent parties is enough. Where the text does not settle a kind,
the cap is marked as a reading and the tier shows a `?`.

## What it gives

```
go run ./cmd/conformance                                    # grade against the current draft
go run ./cmd/conformance --against conformance/standards/aais-poc-0.1.json   # what moved
go run ./cmd/conformance --assume-proposed                  # if the open proposals were adopted
go test ./cmd/conformance
```

The tests hold three things: every evidence path still exists, every standard grades every
kind of party the facts use, and graded against v0.1 the facts give back exactly the tiers
the register declared. The model reproduces the statement before it is allowed to move it.

## What it shows today

Against the v1.0 draft, three facts drop from Tier 3 to Tier 2: `history-anchored` and
`agent-identified` (a single timestamp authority and a governed ledger are each a trusted
party), and `admitted-on-token` (the domain, on a reading). No fact clears the threshold of
Tier 3, so under that draft nothing here is Proof-of-Control. If the proposal to accept a
threshold of independent parties is adopted, `history-anchored` returns to Tier 3.

What holds most facts at Tier 2 is the same pair throughout: Intel's attestation and
Google's platform. That is the one change that would move the most rows, and it is a
change of trust roots, not of code.

## Not modelled

Tier 4 is a property of the whole chain of interactions, not of one fact's trust list. The
tool marks a fact that refuses rather than reports (`enforces`) as a Tier 4 candidate once
it reaches Tier 3, and no further.

## Next, if this is taken up

- Generate the claims table of `statement.md` and the register from the facts and one
  standard file, so the statement cannot drift from the release it describes.
- Keep a standard file per draft as the working group publishes them; the diff between two
  files is the comment to send them.
