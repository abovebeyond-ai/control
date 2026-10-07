package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The list is read with the gateway's Portal token, kept when a read fails, and an entry
// leaves only at its capability's expiry.
func TestTheRevokedListHoldsUntilExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	answer, status := `{"revoked": [{"jti": "a", "exp": 1800003600, "since": "14:00"}, {"jti": "old", "exp": 1799999000, "since": "09:00"}]}`, 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer portal" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(answer))
	}))
	defer srv.Close()
	l := newRevokedList(func() time.Time { return now })
	if err := l.pull(srv.Client(), srv.URL, "portal"); err != nil {
		t.Fatal(err)
	}
	if since, ok := l.Revoked("a"); !ok || since != "14:00" {
		t.Fatalf("a: %q %v", since, ok)
	}
	if _, ok := l.Revoked("old"); ok {
		t.Fatal("an expired capability needs no entry")
	}
	if _, ok := l.Revoked("b"); ok {
		t.Fatal("b was never ended")
	}

	// Portal fails, then answers without a: neither lifts the entry before its expiry.
	status = 503
	if err := l.pull(srv.Client(), srv.URL, "portal"); err == nil {
		t.Fatal("a 503 is an error")
	}
	status, answer = 200, `{"revoked": []}`
	if err := l.pull(srv.Client(), srv.URL, "portal"); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Revoked("a"); !ok {
		t.Fatal("an ended word is not restored by a list that leaves it out")
	}
	if err := l.pull(srv.Client(), srv.URL, "wrong"); err == nil {
		t.Fatal("without the token Portal answers 401")
	}

	now = now.Add(2 * time.Hour)
	if _, ok := l.Revoked("a"); ok {
		t.Fatal("past its expiry the capability is refused by its own exp")
	}
	_ = l.pull(srv.Client(), srv.URL, "portal")
	if len(l.entries) != 0 {
		t.Fatalf("expired entries are dropped: %v", l.entries)
	}
}
