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

**Closing the residual path.** The VM is provisioned entirely by its boot script from a
pinned release, so it needs no operator inside it. The intended custody configuration, to be
applied at service mode:

1. OS Login disabled for the instance and the IAP SSH firewall rule removed; the only
   administrative channel is the serial console, disabled as well. Upgrades are a new
   instance from the boot script, which generates a new key, publishes it in the DID log,
   and retires the old one; the old instance is deleted. The chain rotates with the
   measurement, as it does today.
2. Break-glass: re-enabling the firewall rule and OS Login is a project-level change that
   Google Cloud's audit log records with the identity and the time; the disclosure names
   that log as the record of every operator access. A break-glass that touched the key
   file is followed by a key rotation and a note in the DID log.

Until step 1 is applied, the claim register says so.

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
