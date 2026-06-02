//go:build linux

package spawn

import (
	"context"
	"os"
	"os/exec"
)

func elevated(ctx context.Context, exe string, args ...string) error {
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd := exec.CommandContext(ctx, "pkexec", append([]string{exe}, args...)...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		return cmd.Start()
	}
	cmd := exec.CommandContext(ctx, "sudo", append([]string{exe}, args...)...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Start()
}
