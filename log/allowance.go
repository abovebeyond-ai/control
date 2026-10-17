package log

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
	_ "time/tzdata" // the day is Brussels' day, also in an image without a zone database
)

// allowanceZone is where a day of a daily allowance starts and ends.
var allowanceZone = func() *time.Location {
	z, err := time.LoadLocation("Europe/Brussels")
	if err != nil {
		panic(err)
	}
	return z
}()

// AllowanceDay is the calendar day, in Brussels, that t counts against.
func AllowanceDay(t time.Time) string { return t.In(allowanceZone).Format("2006-01-02") }

// SpentOn sums what the orders under a signer's word added to their day, in cents, from
// allowance.jsonl. Durable on purpose: a restart that forgets the day would give the whole
// allowance again.
func (s *Store) SpentOn(signer, day string) (int64, error) {
	raw, err := os.ReadFile(filepath.Join(s.Dir, "allowance.jsonl"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var sum int64
	for _, line := range strings.Split(string(raw), "\n") {
		var e struct {
			Signer string `json:"signer"`
			Day    string `json:"day"`
			Cents  int64  `json:"cents"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Signer == signer && e.Day == day {
			sum += e.Cents
		}
	}
	return sum, nil
}

// AddSpent counts cents (negative when an order went down) against a signer's day; ref names
// the action, so a reader can find the record each line came from.
func (s *Store) AddSpent(signer, day string, cents int64, ref string) error {
	line, _ := json.Marshal(map[string]any{"signer": signer, "day": day, "cents": cents, "action": ref, "at": time.Now().UTC().Format(time.RFC3339)})
	f, err := os.OpenFile(filepath.Join(s.Dir, "allowance.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
