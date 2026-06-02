//go:build windows

package spawn

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// guiEventHandle stays open for the GUI process lifetime. SignalGUIExit sets it
// so the elevated helper can shut down without relying on TCP or parent PID.
var guiEventHandle windows.Handle

// CreateGUIEvent creates a manual-reset event the GUI holds until exit.
func CreateGUIEvent() (string, error) {
	name := fmt.Sprintf("Local\\SNI-Spoofing-GUI-%d", os.Getpid())
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateEvent(nil, 1, 0, ptr)
	if err != nil {
		return "", err
	}
	guiEventHandle = h
	return name, nil
}

// SignalGUIExit wakes helpers waiting on the GUI shutdown event.
func SignalGUIExit() {
	if guiEventHandle == 0 {
		return
	}
	_ = windows.SetEvent(guiEventHandle)
}
