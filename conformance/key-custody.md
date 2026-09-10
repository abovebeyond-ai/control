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

Signs new versions of `did.jsonl`, that is, changes to which keys are valid. Today a JWK
file in `~/.config/proveml` on the operator's laptop, readable by the operator. From
11 September: token A (YubiKey 5C NFC, PIV slot, Ed25519, PIN-protected, non-exportable),
with the pre-rotated next key on token B kept elsewhere. A signature then needs the token
and the PIN; the key cannot be copied. Runbook: `scripts/README.md` in the site repository.

## The hands' submission key

The in-process key above doubles as the hand's identity for submissions (row 5.1.2): the
gateway's grant names its public key, and every submission is signed with it. Custody is
the box's; a stolen key lets someone submit proposals within the grant, which the gateway
still judges and records, and nothing more.

## The client token and the tunnel account

Bearer secrets, not signing keys: the client token guards the gateway's submit endpoint,
the service account key opens Google's tunnel. Both live in `elixir-secrets/control/`,
mode 0600, and both are revocable in a minute without touching any chain.
