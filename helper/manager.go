package helper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"sni-spoofing-go/guiapi"
	"sni-spoofing-go/helper/spawn"
	"sni-spoofing-go/privilege"
)

const spawnTimeout = 60 * time.Second

var ErrNotConnected = errors.New("helper not connected")

// ProgressFunc receives human-readable status while connecting to the helper.
type ProgressFunc func(message string)

// Manager spawns and maintains a connection to the privileged helper.
type Manager struct {
	exe     string
	handler EventHandler

	mu           sync.Mutex
	client       *Client
	ensureMu     sync.Mutex
	guiEventOnce sync.Once
	guiEventName string
}

func NewManager(exe string, handler EventHandler) *Manager {
	m := &Manager{exe: exe, handler: handler}
	m.ensureGUIEvent()
	return m
}

func (m *Manager) Ensure(ctx context.Context, progress ProgressFunc) (*Client, error) {
	if client := m.connectedClient(); client != nil {
		return client, nil
	}

	m.ensureMu.Lock()
	defer m.ensureMu.Unlock()

	if client := m.connectedClient(); client != nil {
		return client, nil
	}

	addr, token, err := reserveLoopbackPort()
	if err != nil {
		return nil, err
	}

	args := []string{
		"-helper",
		"-listen", addr,
		"-token", token,
		"-parent-pid", strconv.Itoa(os.Getpid()),
	}
	if m.guiEventName != "" {
		args = append(args, "-gui-event", m.guiEventName)
	}
	if progress != nil {
		progress("Requesting elevation — approve the UAC prompt to continue…")
	}
	if err := spawn.Elevated(ctx, m.exe, args...); err != nil {
		return nil, err
	}

	if progress != nil {
		progress("Waiting for privileged helper…")
	}
	client, err := m.dialWithRetry(ctx, addr, token, progress)
	if err != nil {
		go shutdownHelperAt(addr, token)
		return nil, fmt.Errorf("%w (see %s)", err, LogFileHint())
	}

	m.mu.Lock()
	m.client = client
	m.mu.Unlock()
	return client, nil
}

// Stop sends stop to the existing helper without spawning a new one.
func (m *Manager) Stop(ctx context.Context) error {
	client := m.connectedClient()
	if client == nil {
		return ErrNotConnected
	}
	return client.Stop(ctx)
}

func (m *Manager) connectedClient() *Client {
	m.mu.Lock()
	client := m.client
	m.mu.Unlock()
	if client == nil || client.IsClosed() {
		return nil
	}
	return client
}

func (m *Manager) dialHandler() EventHandler {
	base := m.handler
	return EventHandler{
		OnLog:        base.OnLog,
		OnStatus:     base.OnStatus,
		OnTestResult: base.OnTestResult,
		OnDisconnect: func(err error) {
			m.mu.Lock()
			m.client = nil
			m.mu.Unlock()
			if base.OnDisconnect != nil {
				base.OnDisconnect(err)
			}
		},
	}
}

func (m *Manager) dialWithRetry(ctx context.Context, addr, token string, progress ProgressFunc) (*Client, error) {
	client, err := dialLoop(ctx, addr, token, m.dialHandler(), time.Now().Add(spawnTimeout), progress)
	if err == nil {
		return client, nil
	}
	return nil, fmt.Errorf("connect helper: %w (did you approve %s?)", err, privilege.Hint())
}

func dialLoop(ctx context.Context, addr, token string, handler EventHandler, deadline time.Time, progress ProgressFunc) (*Client, error) {
	var lastErr error
	nextNote := time.Now()
	for {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		client, err := Dial(dialCtx, addr, token, handler)
		cancel()
		if err == nil {
			return client, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return nil, lastErr
		}
		if progress != nil && time.Now().After(nextNote) {
			progress("Still waiting for privileged helper…")
			nextNote = time.Now().Add(5 * time.Second)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// shutdownHelperAt best-effort closes a helper that was spawned but never connected.
func shutdownHelperAt(addr, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := dialLoop(ctx, addr, token, EventHandler{}, time.Now().Add(5*time.Second), nil)
	if err == nil {
		_ = client.Close()
	}
}

func (m *Manager) ensureGUIEvent() {
	m.guiEventOnce.Do(func() {
		name, err := spawn.CreateGUIEvent()
		if err != nil {
			if m.handler.OnLog != nil {
				m.handler.OnLog(guiapi.LogEvent{
					Level:   "warn",
					Message: fmt.Sprintf("GUI shutdown event unavailable (%v); helper cleanup relies on IPC only", err),
				})
			}
			return
		}
		m.guiEventName = name
	})
}

func (m *Manager) Close() error {
	spawn.SignalGUIExit()
	m.mu.Lock()
	client := m.client
	m.client = nil
	m.mu.Unlock()
	if client == nil {
		return nil
	}
	return client.Close()
}

func reserveLoopbackPort() (addr, token string, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", err
	}
	defer ln.Close()
	token, err = randomToken()
	if err != nil {
		return "", "", err
	}
	return ln.Addr().String(), token, nil
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
