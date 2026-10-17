package capability

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

// PasskeyPrefix opens a capability a person signed with a passkey: the same payload as an
// Ed25519 capability, carried with what WebAuthn needs to check it.
//
//	wa1.<payload>.<authenticatorData>.<clientDataJSON>.<signature, DER>
//
// each part base64url. The passkey signs authenticatorData || SHA-256(clientDataJSON), and
// clientDataJSON's challenge is base64url(SHA-256(payload)), so the signature covers the
// payload bytes and nothing the relay that carried it could change.
const PasskeyPrefix = "wa1"

// Party is the relying party a passkey was made for: its RP ID (the host) and the origins an
// assertion may come from (the site, and the Android app as android:apk-key-hash:...).
type Party struct {
	RPID    string   `json:"rp_id"`
	Origins []string `json:"origins"`
}

// Passkey is a passkey capability split into its parts.
type Passkey struct {
	Payload    Payload
	Raw        []byte // the payload bytes, canonical JSON
	AuthData   []byte
	ClientData []byte
	Signature  []byte
}

// Challenge is what the passkey must sign over for these payload bytes.
func Challenge(payload []byte) string {
	sum := sha256.Sum256(payload)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IsPasskey says whether a token is in the passkey form.
func IsPasskey(token string) bool { return strings.HasPrefix(token, PasskeyPrefix+".") }

// ParsePasskey splits a passkey capability without verifying it, and refuses payload bytes
// that are not canonical JSON.
func ParsePasskey(token string) (Passkey, error) {
	var k Passkey
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[0] != PasskeyPrefix {
		return k, errors.New("a passkey capability is wa1 and four base64url parts joined by dots")
	}
	var raws [4][]byte
	for i, part := range parts[1:] {
		b, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return k, fmt.Errorf("part %d of the passkey capability is not base64url", i+1)
		}
		raws[i] = b
	}
	k.Raw, k.AuthData, k.ClientData, k.Signature = raws[0], raws[1], raws[2], raws[3]
	if err := canonical.Check(k.Raw); err != nil {
		return k, fmt.Errorf("the capability: %w", err)
	}
	if err := json.Unmarshal(k.Raw, &k.Payload); err != nil {
		return k, err
	}
	return k, nil
}

// clientData is the part of clientDataJSON the gateway reads.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// Flags of authenticatorData the gateway requires: the person was present (UP) and verified
// by the device, with a fingerprint, a face or a PIN (UV).
const (
	flagUP = 0x01
	flagUV = 0x04
)

// VerifyPasskey holds a passkey capability to the holder's P-256 key, the relying party, and
// then to the same gateway, agent and time as an Ed25519 capability: the challenge is the
// payload's digest, the type a get, the origin one the party names, the RP ID hash the
// party's, user presence and verification both set, and the ES256 signature over
// authenticatorData || SHA-256(clientDataJSON) verifies under the key. It returns the payload,
// which the gateway intersects with the grant as it does any capability.
func VerifyPasskey(token string, holder *ecdsa.PublicKey, party Party, audience, subject string, now time.Time) (Payload, error) {
	k, err := ParsePasskey(token)
	if err != nil {
		return k.Payload, err
	}
	p := k.Payload
	var cd clientData
	if err := json.Unmarshal(k.ClientData, &cd); err != nil {
		return p, fmt.Errorf("the passkey's clientDataJSON does not parse: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return p, fmt.Errorf("the passkey's clientDataJSON is of type %q, not webauthn.get", cd.Type)
	}
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(Challenge(k.Raw))) != 1 {
		return p, errors.New("the passkey signed another challenge than this payload's digest")
	}
	if cd.CrossOrigin {
		return p, errors.New("the passkey was asked from a frame of another origin")
	}
	if !contains(party.Origins, cd.Origin) {
		return p, fmt.Errorf("the passkey was asked from %s, an origin the gateway does not accept", cd.Origin)
	}
	if len(k.AuthData) < 37 {
		return p, errors.New("the passkey's authenticatorData is shorter than 37 bytes")
	}
	rp := sha256.Sum256([]byte(party.RPID))
	if party.RPID == "" || subtle.ConstantTimeCompare(k.AuthData[:32], rp[:]) != 1 {
		return p, fmt.Errorf("the passkey was made for another relying party than %s", party.RPID)
	}
	if k.AuthData[32]&flagUP == 0 {
		return p, errors.New("the passkey does not say a person was present")
	}
	if k.AuthData[32]&flagUV == 0 {
		return p, errors.New("the passkey does not say the person was verified on the device")
	}
	if holder == nil {
		return p, errors.New("no key to hold the passkey to")
	}
	cdHash := sha256.Sum256(k.ClientData)
	signed := sha256.Sum256(append(append([]byte{}, k.AuthData...), cdHash[:]...))
	if !ecdsa.VerifyASN1(holder, signed[:], k.Signature) {
		return p, errors.New("the passkey's signature does not verify under the holder's key")
	}
	return p, p.holds(audience, subject, now)
}

// holds is what every capability is held to once its signature verifies: this gateway, this
// agent, and the time.
func (p Payload) holds(audience, subject string, now time.Time) error {
	if p.Audience != audience {
		return fmt.Errorf("the capability is for %s, not this gateway", p.Audience)
	}
	if p.Subject != subject {
		return fmt.Errorf("the capability is for %s, not this agent", p.Subject)
	}
	if p.Expires <= now.Unix() {
		return errors.New("the capability has expired")
	}
	if p.IssuedAt > now.Unix()+60 {
		return errors.New("the capability is issued in the future")
	}
	return nil
}
