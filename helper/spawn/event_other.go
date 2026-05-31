//go:build !windows

package spawn

// CreateGUIEvent is a no-op off Windows; callers use parent PID polling instead.
func CreateGUIEvent() (string, error) {
	return "", nil
}

// SignalGUIExit is a no-op off Windows.
func SignalGUIExit() {}
