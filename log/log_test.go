package log

import (
	"os"
	"path/filepath"
	"testing"
)

// The secondary log lives beside the store, so an unwritable store still gets its
// failure recorded (row 7.6.1); the halt drill of 10 September 2026 found it inside.
func TestTheFailureLogSurvivesAnUnwritableStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(s.Dir, 0o750)
	if err := s.RecordFailure(map[string]any{"error": "disk"}); err != nil {
		t.Fatalf("the failure could not be recorded beside an unwritable store: %v", err)
	}
	if s.Failures() != 1 || filepath.Dir(s.FailuresPath()) != dir {
		t.Fatalf("failures %d at %s", s.Failures(), s.FailuresPath())
	}
}
