//go:build windows

package parentwatch

import (
	"context"
	"time"

	"golang.org/x/sys/windows"
)

const stillActive = 259

// Wait blocks until the GUI process exits. The helper listens for guiEvent to be
// signaled on intentional shutdown, and polls guiPID as a fallback for crashes.
func Wait(ctx context.Context, guiPID int, eventName string) {
	eventDone := make(chan struct{})
	if eventName != "" {
		go func() {
			if waitEventSignaled(eventName) {
				close(eventDone)
			}
		}()
	}

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-eventDone:
			return
		default:
		}
		if guiPID > 0 && !processAlive(guiPID) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-eventDone:
			return
		case <-ticker.C:
		}
	}
}

// waitEventSignaled returns true only after the event is actually signaled.
// OpenEvent failure does not count as GUI exit.
func waitEventSignaled(name string) bool {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false
	}
	h, err := windows.OpenEvent(windows.SYNCHRONIZE, false, ptr)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	r, err := windows.WaitForSingleObject(h, windows.INFINITE)
	if err != nil {
		return false
	}
	return r == windows.WAIT_OBJECT_0
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Cannot query across a boundary — assume alive and rely on gui-event signal.
		return true
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code == stillActive
}
