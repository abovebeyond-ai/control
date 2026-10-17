package log

import (
	"testing"
	"time"
)

// A day is Brussels' day: the sums of one signer's orders start again after midnight there, not
// at midnight UTC, and survive the store being opened again.
func TestADailyAllowanceRollsOverAtMidnightInBrussels(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	late := time.Date(2026, 10, 17, 21, 30, 0, 0, time.UTC) // 23:30 in Brussels (CEST)
	early := late.Add(time.Hour)                            // 00:30 on the 18th in Brussels, still the 17th in UTC
	if AllowanceDay(late) != "2026-10-17" || AllowanceDay(early) != "2026-10-18" {
		t.Fatalf("%s %s", AllowanceDay(late), AllowanceDay(early))
	}
	s.AddSpent("acme#shane", AllowanceDay(late), 151900, "a1")
	s.AddSpent("acme#shane", AllowanceDay(late), -20000, "a2")
	s.AddSpent("acme#robby", AllowanceDay(late), 79800, "a3")
	s.AddSpent("acme#shane", AllowanceDay(early), 45600, "a4")
	again, _ := Open(dir)
	if n, err := again.SpentOn("acme#shane", "2026-10-17"); err != nil || n != 131900 {
		t.Fatalf("the 17th: %d %v", n, err)
	}
	if n, _ := again.SpentOn("acme#shane", "2026-10-18"); n != 45600 {
		t.Fatalf("the 18th: %d", n)
	}
	if n, _ := (&Store{Dir: t.TempDir()}).SpentOn("acme#shane", "2026-10-17"); n != 0 {
		t.Fatalf("nothing kept, nothing spent: %d", n)
	}
}
