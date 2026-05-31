package spawn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Elevated starts exe with args using platform elevation (UAC / sudo / pkexec).
func Elevated(ctx context.Context, exe string, args ...string) error {
	if err := elevated(ctx, exe, args...); err != nil {
		return fmt.Errorf("start elevated helper: %w", err)
	}
	return nil
}

// SelfExe returns the path to the running binary.
func SelfExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

func quoteWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func joinWindowsArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = quoteWindowsArg(a)
	}
	return strings.Join(out, " ")
}
