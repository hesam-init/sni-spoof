//go:build linux || darwin

package parentwatch

import (
	"context"
	"os"
	"syscall"
	"time"
)

// Wait blocks until the GUI process exits. eventName is ignored on Unix.
func Wait(ctx context.Context, guiPID int, eventName string) {
	if guiPID <= 0 {
		return
	}
	proc, err := os.FindProcess(guiPID)
	if err != nil {
		return
	}
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
