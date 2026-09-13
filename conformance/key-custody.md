# Key custody (row 7.3.2)

Which keys exist, who can reach them, and what that means for the claim. Written on
9 September 2026; the YubiKey step is planned for 11 September.

## The gateway's evidence key

| where | how it is made | who can reach it | claim |
| --- | --- | --- | --- |
| Hetzner box, in-process gateway (production records today) | Elixir generates a 32-byte seed on first use into `elixir-secrets/control-signing.key`, mode 0600, owner `elixir` | the `elixir` user, root, anyone with the operator's SSH key to that user | Tier 2: the operator can sign |
| Google VM, control gateway (shadow, becomes production at service mode) | the gateway generates the seed on first start into `/var/lib/control/secrets/control-signing.key`, mode 0600, owner `control`, on the VM's disk inside the trust domain; the TDX quote binds the public key | the `control` user; root on the VM; therefore anyone who can log in through IAP with a project role that allows OS login, today the project owner | Tier 3 with a stated assumption: the operator's login to the VM is the residual path |

What the hardware gives: the key was generated inside the measured domain and the quote
says so; memory is encrypted from the hypervisor; the disk is encrypted at rest by Google.
What it does not give: the file is readable by root inside the domain, and the operator can
become root.

**The residual path, closed on 10 September 2026 (about 14:45 UTC).** The VM is
provisioned entirely by its boot script from a pinned release and needs no operator inside
it. The custody configuration as applied:

1. **No login path.** The firewall rule that admitted SSH from Google's IAP range is
   deleted; the VM has no external address; the serial console is not enabled. The only
   port reachable is the gateway's, from the IAP range, and it acts only on a signed
   submission with the client token.
2. **Nothing is copied in.** The secrets (the client token and one GitHub token per
   repository owner the grants name) live in Google Secret Manager, each readable by the
   VM's own service account and nothing else; the boot script fetches them by name, derived
   from the policy. The policy itself is the instance attribute `control-config`, applied at
   every boot. Changing either is a project-level act, applied by a reset, recorded in Google
   Cloud's audit log with the identity and the time.
3. **Upgrades are a reboot.** The boot script installs the pinned release by checksum and
   restarts the gateway; the disk and the key persist across a reset. A new instance from the
   same script generates a new key, which is then published in the DID log under
   `#control-gateway` and the old one retired.
4. **Break-glass** is re-creating the SSH rule (`rehearse.sh breakglass`), which the audit
   log records; it is followed by a key rotation and a note in the DID log.

**What remains, named.** A project owner can snapshot the VM's disk and read the key file
from the snapshot. That is the one path left, it belongs to the Google project's owner role,
and every snapshot is in the audit log. Closing it needs a key that never touches a disk,
which is a later chapter (a fresh key per boot, published by the attestation rather than
by the DID log).

## The DID update key

Signs new versions of `did.jsonl`, that is, changes to which keys are valid. Since
11 September 2026 (log versions 5 and 6): on token A, a YubiKey 5C NFC, serial 39780281,
PIV slot 9c, Ed25519, generated on the token and non-exportable; a signature needs the PIN
and a touch. The pre-rotated next key is on token B, serial 39780275, slot 9d, kept apart
from A. The software keys that signed versions 4 and 5 were deleted: verification needs
only the public keys in the log, and a retired private key could only sign a fork.
Residual: the laptop that runs the ceremony sees the PIN while it is typed; an attacker
who holds token A and its PIN can sign until B rotates it out; losing A and B together
ends the identity, since no seed exists off the tokens. The tokens swap roles at every
rotation (update on one, the committed successor on the other; twelve versions by 13
September 2026), and no retired private key is kept anywhere. Decided on 13 September
2026, after building the alternative: no third successor. A spare as a file in a safe
(`prepare-spare` in the site's script, rehearsed and kept as an option) puts a copy of the
update key in software, which is the one property the tokens bought; a third token in a
safe covers only the case in which both tokens are lost at once. The answer to that case
is custody, not a key: A and B are kept in two places, never together, and the operator
writes down where. Should both be lost, the identity ends and a new one begins, with the
old log readable and every record it covers still verifiable. Runbook: `scripts/README.md`
in the site repository, with what the day taught.

## The hands' submission key

The in-process key above doubles as the hand's identity for submissions (row 5.1.2): the
gateway's grant names its public key, and every submission is signed with it. Custody is
the box's; a stolen key lets someone submit proposals within the grant, which the gateway
still judges and records, and nothing more.

## Portal's ticket key

Signs the capability for one task (rows 4.2.1, 5.1.3), published as `#portal`. Until 11 September
2026 a seed file in Portal's storage on the Forge box, readable by the `forge` user: whoever got
into Portal could take it and sign for good, unseen. Since that evening (log version 7) the key is
in Google Cloud KMS, `control/portal-capability` in europe-west4, Ed25519 at the software
protection level (the HSM level offers no Ed25519), generated there and non-exportable. Portal
holds the key file of a service account with two roles on that one key, `signerVerifier` and
`publicKeyViewer`, at `/home/forge/.config/portal/kms-signer.json` (0600). Every signature is in
Google's audit log with the caller. Residual: whoever holds that file signs while it is valid; the
cure is revocation, and the log says what was signed meanwhile. The seed file is deleted.

## The operator's keys

Sign the workbench's capability, the operator's word for a session on the operator's
machine (rows 4.2.2, 4.1.6, 6.3.1), published as `#operator` and `#operator-2`. Since 13
September 2026 (successor log, version 1): one Ed25519 key in PIV slot 9c of each of two
YubiKey 5C NFC (serials 39780275 and 39780281), generated on the token by `ykman` with
`--pin-policy once --touch-policy always`, non-exportable, a touch on every signature and
the PIN per session. Either key admits; whichever token is in the operator's pocket
works. Custody is the operator's person. Residual: a stolen token with its PIN signs until
the fragment is removed from the log (one update signed with the other token), and the
grant bounds what any signature can allow; a token cannot display what it signs, so the
tool that shows the payload before the touch (`hand.mjs admit`) must be the tool the
operator ran. What is left as a file, and said so: the identity's own key `#key-1`
(`~/.config/proveml/abovebeyond-signing.jwk`), which signs credentials and vouches for a
successor document; its move to a token is the next step.

## The identity's update keys and the spare

Sign the DID log itself, never a record or a capability. Since the successor: the update
key in PIV slot 9d of the token that signed last, the next key in slot 9d of the other,
and a spare in slot 9a of the signing token, all generated on the tokens; every version
commits two next-key hashes, the next key's and the spare's, so one destroyed slot never
ends the log (the first identifier ended that way on 13 September 2026: one committed
hash, and a key generation on the wrong token). Both tokens lost ends the identity; a
successor would then need a new identifier that the old cannot vouch for. Which token holds
which role is read from the descriptor files in `~/.config/proveml/`, never from memory,
before any command that touches a token.

## The client token and the tunnel account

Bearer secrets, not signing keys: the client token guards the gateway's submit endpoint,
the service account key opens Google's tunnel. Both live in `elixir-secrets/control/`,
mode 0600, and both are revocable in a minute without touching any chain.
