// Package canonical is the canonical form an evidence digest commits to: RFC
// 8785 (JSON Canonicalization Scheme) as the Proof-of-Control standard pins
// it down in schema/canonicalization.md. Keys sorted by UTF-16 code unit, no
// whitespace, minimal escapes, non-ASCII literal, digests tagged with their
// algorithm, and no floating point in a claim set: a float is refused, not
// formatted, because number formatting is where canonical forms go wrong
// quietly.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const Algorithm = "sha-256"

// ErrFloat is returned for a non-integer number: the claim set forbids it.
var ErrFloat = errors.New("the claim set forbids floating point; see canonicalization.md")

// Encode returns the canonical bytes of a value. Maps become objects, slices
// arrays; json.Number and integers are written as integers; float64 is
// accepted only when it is a whole number within the safe range.
func Encode(v any) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(x, 10))
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			return fmt.Errorf("%w (found %s)", ErrFloat, x.String())
		}
		b.WriteString(x.String())
	case float64:
		if x != math.Trunc(x) || math.Abs(x) >= 1<<53 {
			return fmt.Errorf("%w (found %v)", ErrFloat, x)
		}
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := encode(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = v
		}
		return encode(b, m)
	default:
		// Anything else goes through JSON and back, so structs canonicalise too.
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		var generic any
		if err := dec.Decode(&generic); err != nil {
			return err
		}
		return encode(b, generic)
	}
	return nil
}

// lessUTF16 orders two strings by UTF-16 code units, as RFC 8785 requires;
// UTF-8 byte order differs above the basic multilingual plane.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// SHA256 of raw bytes, lowercase hex.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Digest is the lowercase hex sha256 of the canonical form of a value.
func Digest(v any) (string, error) {
	b, err := Encode(v)
	if err != nil {
		return "", err
	}
	return SHA256(b), nil
}

// Tag is the wire form of a digest: algorithm-tagged, so evidence written
// before a hash migration is still interpretable after one.
func Tag(hex string) string { return Algorithm + ":" + hex }

// Untag refuses an untagged, foreign or malformed digest rather than guessing.
func Untag(digest string) (string, error) {
	alg, value, ok := strings.Cut(digest, ":")
	if !ok || value == "" {
		return "", fmt.Errorf("untagged digest %q: the algorithm is mandatory", digest)
	}
	if alg != Algorithm {
		return "", fmt.Errorf("unsupported digest algorithm %q", alg)
	}
	if len(value) != 64 || strings.ToLower(value) != value || strings.Trim(value, "0123456789abcdef") != "" {
		return "", fmt.Errorf("digest %q is not 64 lowercase hex characters", digest)
	}
	return value, nil
}
