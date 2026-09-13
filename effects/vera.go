package effects

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/policy"
)

// Vera performs the review hand's effects on the Vera app (13 September 2026, the second
// hand on the gateway): publishing a review page, inviting a person, and sealing a review
// root. The app's operator token lives in the gateway's secrets as vera-token, never on
// the laptop that builds the page; the seal key is made inside the machine on first use,
// as the gateway's own key was, and the register names it as #vera. A judgement is never
// an effect here: those are people's, on the page.
//
// Resources are "vera/<review id>": one review per permit line, the id as the app knows it.
type Vera struct {
	SecretsDir string
	Client     *http.Client
	Base       string // https://vera.abovebeyond.ai
}

func (v Vera) Kinds() []string {
	return []string{"review.publish", "review.invite", "review.sign"}
}

var reviewID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ReviewIDOf reads the review id from a "vera/<id>" resource.
func ReviewIDOf(resource string) (string, bool) {
	prefix, id, ok := strings.Cut(resource, "/")
	if !ok || prefix != "vera" || !reviewID.MatchString(id) {
		return "", false
	}
	return id, true
}

func (v Vera) token() (string, error) {
	raw, err := os.ReadFile(filepath.Join(v.SecretsDir, "vera-token"))
	if err != nil {
		return "", errors.New("no Vera token in the gateway's secrets")
	}
	return strings.TrimSpace(string(raw)), nil
}

// SealKey is the #vera key: made in the secrets directory on first use, never leaving.
func (v Vera) SealKey() (ed25519.PrivateKey, error) {
	path := filepath.Join(v.SecretsDir, "vera-seal.key")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s does not hold a 32-byte hex seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// SealMessage is what #vera signs for a review root: a fixed prefix, the review id and
// the root, so a signature cannot be lifted onto another review or read as anything else.
func SealMessage(id, root string) []byte {
	return []byte("vera-review-root\x00" + id + "\x00" + root)
}

func (v Vera) Perform(ctx context.Context, a policy.Action) Outcome {
	id, ok := ReviewIDOf(a.Resource)
	if !ok {
		return Outcome{Error: "resource is not vera/<review id>"}
	}
	switch a.Kind {
	case "review.sign":
		// Nothing leaves the machine but a signature: the root comes in the parameters,
		// the working beside the record says every reading was judged, and the record
		// carries the signature and the key. The app learns of it from the record.
		root, _ := a.Params["root"].(string)
		if _, err := canonical.Untag(root); err != nil {
			return Outcome{Error: "review.sign needs params.root, a sha-256: tag of the review root"}
		}
		key, err := v.SealKey()
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		sig := ed25519.Sign(key, SealMessage(id, root))
		return Outcome{OK: true, Detail: map[string]any{
			"review": id, "root": root, "signature": hex.EncodeToString(sig),
			"key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "role": "#vera",
		}}
	}
	token, err := v.token()
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	base := v.Base
	if base == "" {
		base = "https://vera.abovebeyond.ai"
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	call := func(method, path string, body any) (int, map[string]any, error) {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(body)
		req, err := http.NewRequestWithContext(ctx, method, base+path, &buf)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return res.StatusCode, out, nil
	}
	switch a.Kind {
	case "review.publish":
		// The page travels attached, digest bound to params.page_sha256 the way a push
		// binds its files: what was judged is what is published.
		want, _ := a.Params["page_sha256"].(string)
		files, err := DecodeFiles(a.Attached["files"])
		if err != nil || len(files) != 1 {
			return Outcome{Error: "review.publish needs one file attached, the page: " + fmt.Sprint(err)}
		}
		if got, _ := FilesDigest(files); got != want {
			return Outcome{Error: "the attached page does not match params.page_sha256"}
		}
		page, err := base64.StdEncoding.DecodeString(files[0].Content)
		if err != nil {
			return Outcome{Error: "the page is not base64"}
		}
		title, _ := a.Params["title"].(string)
		by, _ := a.Params["by"].(string)
		body := map[string]any{"page": string(page), "title": title, "by": "the control gateway" + map[bool]string{true: " for " + by, false: ""}[by != ""]}
		if s, ok := a.Attached["signoffs"]; ok && s != nil {
			body["signoffs"] = s
		}
		status, res, err := call("PUT", "/r/"+id, body)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 200 {
			return Outcome{Error: fmt.Sprintf("Vera answered %d: %v", status, res["error"])}
		}
		return Outcome{OK: true, Detail: map[string]any{"review": id, "url": res["url"], "page_sha256": want}}
	case "review.invite":
		email, _ := a.Params["email"].(string)
		if !strings.Contains(email, "@") {
			return Outcome{Error: "review.invite needs params.email"}
		}
		status, res, err := call("POST", "/r/"+id+"/people/invite", map[string]any{"email": email, "by": "the control gateway"})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 200 {
			return Outcome{Error: fmt.Sprintf("Vera answered %d: %v", status, res["error"])}
		}
		return Outcome{OK: true, Detail: map[string]any{"review": id, "email": email, "delivery": res["delivery"]}}
	}
	return Outcome{Error: "no adapter for " + a.Kind}
}
