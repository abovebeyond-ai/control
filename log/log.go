// Package log is the durable evidence log: one append-only JSON Lines file
// per agent, a secondary log for the times the primary could not be written,
// and attachments beside a record (the premises a token's digests cover).
//
// Write-before-release is only a promise if the write is durable when Append
// returns: the line is flushed and fsynced under an exclusive lock. A log
// that cannot be written returns ErrUnavailable and the gateway fails closed.
package log

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abovebeyond-ai/control/evidence"
)

// ErrUnavailable: the store could not be written; nothing may be released.
var ErrUnavailable = errors.New("evidence store unavailable")

var unsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Store is a directory of agent logs.
type Store struct {
	Dir       string
	Available bool // false models pipeline failure, for the fail-closed test
}

// Open a store at a directory, creating it.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Store{Dir: dir, Available: true}, nil
}

// Safe is the agent id as a file name: a did:webvh with a fragment keeps only
// what a filesystem likes. Agents() returns these; Records accepts either form.
func Safe(agent string) string { return unsafe.ReplaceAllString(agent, "_") }

func (s *Store) agentDir(agent string) string { return filepath.Join(s.Dir, Safe(agent)) }
func (s *Store) file(agent string) string     { return s.agentDir(agent) + ".jsonl" }

// Append writes one record durably.
func (s *Store) Append(agent string, token evidence.Token) error {
	if !s.Available {
		return ErrUnavailable
	}
	line, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	f, err := os.OpenFile(s.file(agent), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return nil
}

// Records of an agent, in the order written.
func (s *Store) Records(agent string) ([]evidence.Token, error) {
	raw, err := os.ReadFile(s.file(agent))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []evidence.Token
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		var tok evidence.Token
		if err := dec.Decode(&tok); err != nil {
			return nil, fmt.Errorf("line %d of the evidence log for %s is not a record: %v", i, agent, err)
		}
		out = append(out, tok)
	}
	return out, nil
}

// Agents that have a log here.
func (s *Store) Agents() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") && e.Name() != "failures.jsonl" {
			out = append(out, strings.TrimSuffix(e.Name(), ".jsonl"))
		}
	}
	sort.Strings(out)
	return out, nil
}

// RecordFailure writes to the secondary log; if that fails too, the error says so.
func (s *Store) RecordFailure(info map[string]any) error {
	info["at"] = time.Now().UTC().Format(time.RFC3339)
	line, _ := json.Marshal(info)
	f, err := os.OpenFile(filepath.Join(s.Dir, "failures.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return errors.New("neither the evidence log nor the failure log could be written")
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Attach keeps material beside a record, by step: what a token's digests
// cover, so a stranger can replay the check. After the record, never instead.
func (s *Store) Attach(agent string, step int, name string, data any) error {
	dir := filepath.Join(s.agentDir(agent), name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, strconv.Itoa(step)+".json"), append(raw, '\n'), 0o640)
}

// Attachment reads material beside a record; nil when there is none.
func (s *Store) Attachment(agent string, step int, name string, into any) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(s.agentDir(agent), name, strconv.Itoa(step)+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, into)
}
