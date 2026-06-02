package helper

import (
	"testing"
)

func TestReserveLoopbackPort(t *testing.T) {
	addr, token, err := reserveLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	if addr == "" || token == "" {
		t.Fatal("empty addr or token")
	}
}
