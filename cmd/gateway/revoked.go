package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// revokedConfig is where the gateway reads the capabilities the owner ended before they
// expired. A capability is a signed token the gateway checks on its own, so without this
// list a word ended at Portal still stood here until its expiry, up to the end of a working
// set. The list only takes away: it needs no signature of the owner, as a narrowing of the
// policy needs none, and a Portal that lies in it can stop work, which it can already do by
// issuing nothing.
type revokedConfig struct {
	// URL answers GET with {"revoked": [{"jti", "exp", "since"}]}: every capability ended
	// early that has not expired yet. Read with the gateway's Portal token.
	URL string `json:"url"`
	// Every is how often the list is read, in seconds (default 30).
	Every int `json:"every,omitempty"`
}

type revokedEntry struct {
	JTI   string `json:"jti"`
	Exp   int64  `json:"exp"`
	Since string `json:"since"`
}

// revokedList is the last list read, in memory. A read that fails keeps the last list: an
// entry leaves only by its expiry, never because Portal could not be reached.
type revokedList struct {
	mu      sync.RWMutex
	entries map[string]revokedEntry
	read    time.Time
	clock   func() time.Time
}

func newRevokedList(clock func() time.Time) *revokedList {
	return &revokedList{entries: map[string]revokedEntry{}, clock: clock}
}

// Revoked is the gateway's question: has the owner ended this capability, and since when.
func (l *revokedList) Revoked(jti string) (string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	e, ok := l.entries[jti]
	if !ok || e.Exp <= l.clock().Unix() {
		return "", false
	}
	return e.Since, true
}

// pull reads the list once and merges it into what is held; entries past their expiry go.
func (l *revokedList) pull(client *http.Client, url, token string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("revocations answered %d", resp.StatusCode)
	}
	var page struct {
		Revoked []revokedEntry `json:"revoked"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return fmt.Errorf("revocations: %w", err)
	}
	now := l.clock().Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range page.Revoked {
		if e.JTI != "" && e.Exp > now {
			l.entries[e.JTI] = e
		}
	}
	for jti, e := range l.entries {
		if e.Exp <= now {
			delete(l.entries, jti)
		}
	}
	l.read = l.clock()
	return nil
}

// follow reads the list once before the gateway serves, then every interval, for as long as
// the gateway runs.
func (l *revokedList) follow(cfg revokedConfig, token string) {
	client := &http.Client{Timeout: 10 * time.Second}
	every := time.Duration(cfg.Every) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	if err := l.pull(client, cfg.URL, token); err != nil {
		fmt.Fprintf(os.Stderr, "revocations: %v\n", err)
	}
	go func() {
		for range time.Tick(every) {
			if err := l.pull(client, cfg.URL, token); err != nil {
				fmt.Fprintf(os.Stderr, "revocations: %v\n", err)
			}
		}
	}()
}
