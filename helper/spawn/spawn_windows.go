//go:build windows

package spawn

import (
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

func elevated(_ context.Context, exe string, args ...string) error {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString(joinWindowsArgs(args))
	if err != nil {
		return err
	}
	cwd, err := syscall.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return err
	}

	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(cwd)),
		0, // SW_HIDE — helper has no window
	)
	if ret <= 32 {
		return fmt.Errorf("ShellExecute runas failed (code %d)", ret)
	}
	return nil
}

var (
	shell32        = syscall.NewLazyDLL("shell32.dll")
	shellExecuteW  = shell32.NewProc("ShellExecuteW")
)
