//go:build !bindings

package main

// startupVerify runs before wails.Run in normal/desktop builds. Skipped when
// Wails compiles with -tags bindings (binding generation runs before npm build).
func startupVerify() error {
	return verifyEmbeddedFrontend()
}
