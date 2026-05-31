package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"sni-spoofing-go/guiapi"
	"sni-spoofing-go/helper/parentwatch"
	"sni-spoofing-go/privilege"
	"sni-spoofing-go/proxy"
)

// RunServer listens on addr and serves privileged proxy operations over JSON lines.
// guiPID and guiEvent make the helper exit when the GUI process exits.
func RunServer(listenAddr, token string, guiPID int, guiEvent string) error {
	ok, err := privilege.IsElevated()
	if err != nil {
		return fmt.Errorf("privilege check: %w", err)
	}
	if !ok {
		err := fmt.Errorf("helper requires elevated privileges; please %s", privilege.Hint())
		LogHelperError("%v", err)
		return err
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		err = fmt.Errorf("listen %s: %w", listenAddr, err)
		LogHelperError("%v", err)
		return err
	}
	defer ln.Close()

	fmt.Fprintf(os.Stderr, "helper listening on %s\n", ln.Addr().String())

	srv := &server{
		token: token,
	}
	if guiPID > 0 || guiEvent != "" {
		go func() {
			parentwatch.Wait(context.Background(), guiPID, guiEvent)
			LogHelperError("GUI exited (pid=%d event=%q); shutting down helper", guiPID, guiEvent)
			_ = srv.stopAll(true)
			os.Exit(0)
		}()
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		// Ignore failed auth / stray connections; exit only after the
		// authenticated GUI session ends.
		if srv.serveConn(conn) {
			return nil
		}
	}
}

type server struct {
	token string

	mu           sync.Mutex
	running      bool
	cancelFn     context.CancelFunc
	listenAddr   string
	doneCh       chan struct{}
	testing      bool
	testCancelFn context.CancelFunc
	testDoneCh   chan struct{}

	connMu  sync.Mutex
	conn    net.Conn
	enc     *json.Encoder
	writeMu sync.Mutex
}

func (s *server) serveConn(conn net.Conn) (authenticated bool) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var first Envelope
	if err := dec.Decode(&first); err != nil {
		return false
	}
	if first.Type != MsgAuth || first.Token != s.token {
		_ = enc.Encode(Envelope{Type: MsgAuthFail, Message: "invalid auth"})
		return false
	}
	if err := enc.Encode(Envelope{Type: MsgAuthOK}); err != nil {
		return false
	}

	s.connMu.Lock()
	s.conn = conn
	s.enc = enc
	s.connMu.Unlock()
	defer func() {
		s.connMu.Lock()
		if s.conn == conn {
			s.conn = nil
			s.enc = nil
		}
		s.connMu.Unlock()
	}()

	for {
		var env Envelope
		if err := dec.Decode(&env); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("helper decode: %v", err)
			}
			s.endSession()
			return true
		}
		switch env.Type {
		case MsgRequest:
			s.handleRequest(enc, env)
		case MsgShutdown:
			s.endSession()
			return true
		default:
			log.Printf("helper: unexpected message type %q", env.Type)
		}
	}
}

func (s *server) endSession() {
	_ = s.stopAll(true)
}

func (s *server) replyOK(enc *json.Encoder, id int, result any) {
	resp, err := rpcOK(id, result)
	if err != nil {
		s.writeEnvelope(enc, rpcError(id, err))
		return
	}
	s.writeEnvelope(enc, resp)
}

func (s *server) replyErr(enc *json.Encoder, id int, err error) {
	s.writeEnvelope(enc, rpcError(id, err))
}

func (s *server) runAsync(enc *json.Encoder, id int, fn func() (any, error)) {
	go func() {
		result, err := fn()
		if err != nil {
			s.replyErr(enc, id, err)
			return
		}
		s.replyOK(enc, id, result)
	}()
}

func (s *server) handleRequest(enc *json.Encoder, env Envelope) {
	switch env.Method {
	case MethodStart:
		var params ConfigParams
		if err := json.Unmarshal(env.Params, &params); err != nil {
			s.replyErr(enc, env.ID, err)
			return
		}
		cfg := params.Config
		s.runAsync(enc, env.ID, func() (any, error) {
			if err := s.start(cfg); err != nil {
				return nil, err
			}
			return nil, nil
		})
	case MethodStop:
		if err := s.stopAll(false); err != nil {
			s.replyErr(enc, env.ID, err)
			return
		}
		s.replyOK(enc, env.ID, nil)
	case MethodRunTest:
		var params ConfigParams
		if err := json.Unmarshal(env.Params, &params); err != nil {
			s.replyErr(enc, env.ID, err)
			return
		}
		cfg := params.Config
		s.runAsync(enc, env.ID, func() (any, error) {
			return s.runTest(cfg)
		})
	default:
		s.replyErr(enc, env.ID, fmt.Errorf("unknown method %q", env.Method))
	}
}

func (s *server) writeEnvelope(enc *json.Encoder, env Envelope) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := enc.Encode(env); err != nil {
		log.Printf("helper write: %v", err)
	}
}

func (s *server) status() guiapi.ProxyStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return guiapi.ProxyStatus{
		Running:    s.running,
		Testing:    s.testing,
		ListenAddr: s.listenAddr,
	}
}

func (s *server) emit(name string, data any) {
	ev, err := event(name, data)
	if err != nil {
		log.Printf("helper event: %v", err)
		return
	}
	s.connMu.Lock()
	enc := s.enc
	s.connMu.Unlock()
	if enc == nil {
		return
	}
	s.writeEnvelope(enc, ev)
}

func (s *server) start(cfg guiapi.ProxyConfig) error {
	pc, opts, err := guiapi.BuildProxyArgs(cfg, false)
	if err != nil {
		return err
	}
	logSink := &helperLogWriter{srv: s}
	opts.Logger = log.New(logSink, "", 0)

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("proxy is already running")
	}
	if s.testing {
		s.mu.Unlock()
		return errors.New("cannot start the proxy while the test matrix is running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelFn = cancel
	s.running = true
	doneCh := make(chan struct{})
	s.doneCh = doneCh
	selfCancel := doneCh
	s.mu.Unlock()

	ready := make(chan proxy.Ready, 1)
	go func() {
		prev := log.Writer()
		log.SetOutput(logSink)
		defer log.SetOutput(prev)

		err := proxy.Run(ctx, pc, opts, ready)

		s.mu.Lock()
		if s.doneCh == selfCancel {
			s.running = false
			s.cancelFn = nil
			s.listenAddr = ""
		}
		s.mu.Unlock()
		close(doneCh)

		if err != nil && !errors.Is(err, context.Canceled) {
			s.emit("log", guiapi.LogEvent{Level: "error", Message: fmt.Sprintf("proxy exited: %v", err)})
		} else {
			s.emit("log", guiapi.LogEvent{Level: "info", Message: "proxy stopped"})
		}
		s.emit("status", s.status())
	}()

	startTimer := time.NewTimer(proxy.StartReadyTimeout)
	defer startTimer.Stop()

	waitGoroutine := func() {
		cancel()
		t := time.NewTimer(2 * time.Second)
		select {
		case <-doneCh:
		case <-t.C:
		}
		t.Stop()
	}

	select {
	case r := <-ready:
		if r.Err != nil {
			waitGoroutine()
			return fmt.Errorf("proxy start failed: %w", r.Err)
		}
		s.mu.Lock()
		s.listenAddr = r.ListenAddr
		s.mu.Unlock()
		s.emit("log", guiapi.LogEvent{Level: "info", Message: "listening on " + r.ListenAddr})
		s.emit("status", s.status())
		return nil
	case <-startTimer.C:
		waitGoroutine()
		return fmt.Errorf("proxy start timed out after %s", proxy.StartReadyTimeout)
	}
}

func (s *server) stopAll(quiet bool) error {
	s.mu.Lock()
	if !s.running && !s.testing {
		s.mu.Unlock()
		if !quiet {
			s.emit("log", guiapi.LogEvent{Level: "debug", Message: "stop ignored: nothing is running"})
		}
		return nil
	}
	proxyCancel := s.cancelFn
	testCancel := s.testCancelFn
	proxyDone := s.doneCh
	testDone := s.testDoneCh
	s.cancelFn = nil
	s.testCancelFn = nil
	s.mu.Unlock()

	if proxyCancel != nil {
		proxyCancel()
	}
	if testCancel != nil {
		testCancel()
	}
	s.waitForDone(proxyDone, quiet, "proxy goroutine slow to exit; proceeding")
	s.waitForDone(testDone, quiet, "test goroutine slow to exit; proceeding")
	if !quiet {
		s.emit("status", s.status())
	}
	return nil
}

func (s *server) waitForDone(done chan struct{}, quiet bool, warnMsg string) {
	if done == nil {
		return
	}
	t := time.NewTimer(2 * time.Second)
	select {
	case <-done:
	case <-t.C:
		if !quiet {
			s.emit("log", guiapi.LogEvent{Level: "warn", Message: warnMsg})
		}
	}
	t.Stop()
}

func (s *server) runTest(cfg guiapi.ProxyConfig) (guiapi.TestSummary, error) {
	testCfg := cfg
	testCfg.Listen = proxy.DefaultTestListenAddr()

	pc, opts, err := guiapi.BuildProxyArgs(testCfg, true)
	if err != nil {
		return guiapi.TestSummary{}, err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return guiapi.TestSummary{}, errors.New("stop the proxy before running the test matrix")
	}
	if s.testing {
		s.mu.Unlock()
		return guiapi.TestSummary{}, errors.New("a test matrix is already running")
	}
	testCtx, cancel := context.WithCancel(context.Background())
	s.testing = true
	s.testCancelFn = cancel
	s.testDoneCh = make(chan struct{})
	testDone := s.testDoneCh
	s.mu.Unlock()

	s.emit("status", s.status())
	defer func() {
		s.mu.Lock()
		s.testing = false
		s.testCancelFn = nil
		s.mu.Unlock()
		cancel()
		s.emit("status", s.status())
		close(testDone)
	}()

	s.emit("log", guiapi.LogEvent{Level: "info", Message: "running preflight…"})
	pre := proxy.CheckMethodPreconditions(pc.ConnectIP, pc.FakeSNI)
	summary := guiapi.TestSummary{
		Preflight: guiapi.TestPreflight{
			ExternalIP: pre.ExternalIP,
			InternalIP: pre.InternalIP,
			Matched:    pre.Matched,
		},
	}
	if pre.LookupErr != nil {
		return summary, pre.LookupErr
	}
	if pre.InternalIP == "" {
		summary.Preflight.Warning = "internal IP unavailable; running matrix anyway"
		s.emit("log", guiapi.LogEvent{Level: "warn", Message: summary.Preflight.Warning})
	} else if !pre.Matched {
		return summary, pre.MatchErr
	} else {
		s.emit("log", guiapi.LogEvent{Level: "info", Message: fmt.Sprintf("preflight ok (external=%s internal=%s)", pre.ExternalIP, pre.InternalIP)})
	}

	progress := func(r proxy.MatrixResult) {
		row := guiapi.TestResult{
			UTLS:           r.Case.UTLS,
			FakeRepeat:     r.Case.FakeRepeat,
			EnableFragment: r.Case.EnableFragment,
			Pass:           r.Pass,
		}
		if r.Err != nil {
			row.Error = r.Err.Error()
		}
		summary.Results = append(summary.Results, row)
		s.emit("test_result", row)
		if r.Pass {
			summary.Passed++
			s.emit("log", guiapi.LogEvent{Level: "info", Message: fmt.Sprintf("  PASS  utls=%s repeat=%d fragment=%s", r.Case.UTLS, r.Case.FakeRepeat, proxy.FragmentLabel(r.Case.EnableFragment))})
		} else {
			summary.Failed++
			msg := ""
			if r.Err != nil {
				msg = ": " + r.Err.Error()
			}
			s.emit("log", guiapi.LogEvent{Level: "warn", Message: fmt.Sprintf("  FAIL  utls=%s repeat=%d fragment=%s%s", r.Case.UTLS, r.Case.FakeRepeat, proxy.FragmentLabel(r.Case.EnableFragment), msg)})
		}
	}

	if _, err := proxy.RunMethodMatrix(testCtx, pc, opts.Injector, progress); err != nil {
		if errors.Is(err, context.Canceled) {
			s.emit("log", guiapi.LogEvent{Level: "warn", Message: "test matrix cancelled"})
			return summary, nil
		}
		return summary, err
	}
	s.emit("log", guiapi.LogEvent{Level: "info", Message: fmt.Sprintf("matrix done: %d passed / %d failed", summary.Passed, summary.Failed)})
	return summary, nil
}

type helperLogWriter struct {
	srv *server
	mu  sync.Mutex
}

func (w *helperLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	msg := strings.TrimRight(string(p), "\r\n")
	if msg == "" {
		return len(p), nil
	}
	level := "info"
	for _, p := range []struct{ token, lvl string }{
		{"error: ", "error"},
		{"warn: ", "warn"},
		{"debug: ", "debug"},
	} {
		if strings.HasPrefix(msg, p.token) {
			level = p.lvl
			msg = strings.TrimPrefix(msg, p.token)
			break
		}
	}
	w.srv.emit("log", guiapi.LogEvent{Level: level, Message: msg})
	return len(p), nil
}
