package helper

import (
	"log"
	"os"
	"path/filepath"
	"sync"
)

var (
	helperLog     *log.Logger
	helperLogOnce sync.Once
)

func helperLogger() *log.Logger {
	helperLogOnce.Do(func() {
		path, err := logFilePath("helper.log")
		if err != nil {
			helperLog = log.New(os.Stderr, "helper: ", log.LstdFlags)
			return
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			helperLog = log.New(os.Stderr, "helper: ", log.LstdFlags)
			return
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			helperLog = log.New(os.Stderr, "helper: ", log.LstdFlags)
			return
		}
		helperLog = log.New(f, "", log.LstdFlags)
	})
	return helperLog
}

func logHelper(format string, args ...any) {
	helperLogger().Printf(format, args...)
}

func logFilePath(name string) (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sni-spoofing-gui", name), nil
}

func LogFileHint() string {
	path, err := logFilePath("helper.log")
	if err != nil {
		return "helper.log in the app cache directory"
	}
	return path
}

func LogHelperStartup(listenAddr string, parentPID int, guiEvent string, args []string) {
	logHelper("starting helper pid=%d listen=%s gui-event=%q parent-pid=%d argv=%q",
		os.Getpid(), listenAddr, guiEvent, parentPID, redactArgv(args))
}

func redactArgv(args []string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == "-token" {
			out[i+1] = "[redacted]"
		}
	}
	return out
}

func LogHelperError(format string, args ...any) {
	logHelper(format, args...)
}
