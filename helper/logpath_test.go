package helper

import (
	"testing"
)

func TestRedactArgv(t *testing.T) {
	in := []string{"exe", "-helper", "-listen", "127.0.0.1:1", "-token", "secret", "-parent-pid", "99"}
	got := redactArgv(in)
	if got[5] != "[redacted]" {
		t.Fatalf("token not redacted: %q", got[5])
	}
	if got[4] != "-token" {
		t.Fatalf("expected -token flag preserved, got %q", got[4])
	}
}
