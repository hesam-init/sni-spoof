//go:build darwin

package spawn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func elevated(ctx context.Context, exe string, args ...string) error {
	script, err := adminAppleScript(exe, args...)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	// Run (vs Start): wait for the user to approve the macOS admin dialog.
	return cmd.Run()
}

func adminAppleScript(exe string, args ...string) (string, error) {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, shQuote(exe))
	for _, arg := range args {
		parts = append(parts, shQuote(arg))
	}
	// Do not use nohup here: under "with administrator privileges" it fails with
	// "can't detach from console: Inappropriate ioctl for device" and the helper
	// never starts. A plain background job survives once osascript returns.
	shell := fmt.Sprintf("%s > /dev/null 2>&1 &", strings.Join(parts, " "))
	shell = escapeAppleScriptString(shell)
	return fmt.Sprintf(`do shell script "%s" with administrator privileges`, shell), nil
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func escapeAppleScriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
