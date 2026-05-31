package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"sni-spoofing-go/guiapi"
)

const clientCloseTimeout = 2 * time.Second

type EventHandler struct {
	OnLog        func(guiapi.LogEvent)
	OnStatus     func(guiapi.ProxyStatus)
	OnTestResult func(guiapi.TestResult)
	OnDisconnect func(err error)
}

// Client talks to a privileged helper over TCP JSON lines.
type Client struct {
	token   string
	handler EventHandler

	mu      sync.Mutex
	conn    net.Conn
	enc     *json.Encoder
	nextID  int
	pending map[int]chan Envelope
	closed  atomic.Bool

	readDone chan struct{}
	readErr  error
}

func Dial(ctx context.Context, addr, token string, handler EventHandler) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	c := &Client{
		token:    token,
		handler:  handler,
		conn:     conn,
		enc:      json.NewEncoder(conn),
		pending:  make(map[int]chan Envelope),
		readDone: make(chan struct{}),
	}
	if err := c.authenticate(json.NewDecoder(conn)); err != nil {
		conn.Close()
		return nil, err
	}
	go c.readLoop(json.NewDecoder(conn))
	return c, nil
}

func (c *Client) authenticate(dec *json.Decoder) error {
	if err := c.enc.Encode(Envelope{Type: MsgAuth, Token: c.token}); err != nil {
		return err
	}
	var resp Envelope
	if err := dec.Decode(&resp); err != nil {
		return err
	}
	if resp.Type != MsgAuthOK {
		msg := resp.Message
		if msg == "" {
			msg = "helper auth failed"
		}
		return errors.New(msg)
	}
	return nil
}

func (c *Client) readLoop(dec *json.Decoder) {
	defer close(c.readDone)
	defer func() {
		if c.handler.OnDisconnect != nil {
			err := c.readErr
			if err == nil {
				err = io.EOF
			}
			c.handler.OnDisconnect(err)
		}
	}()
	for {
		var env Envelope
		if err := dec.Decode(&env); err != nil {
			c.readErr = err
			c.failPending(err)
			return
		}
		switch env.Type {
		case MsgEvent:
			c.dispatchEvent(env)
		case MsgResponse:
			c.mu.Lock()
			ch := c.pending[env.ID]
			delete(c.pending, env.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- env
			}
		}
	}
}

func (c *Client) failPending(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		ch <- Envelope{Type: MsgResponse, ID: id, Error: err.Error()}
		delete(c.pending, id)
	}
}

func (c *Client) dispatchEvent(env Envelope) {
	switch env.Name {
	case "log":
		if c.handler.OnLog == nil {
			return
		}
		var ev guiapi.LogEvent
		if err := json.Unmarshal(env.Data, &ev); err != nil {
			return
		}
		c.handler.OnLog(ev)
	case "status":
		if c.handler.OnStatus == nil {
			return
		}
		var st guiapi.ProxyStatus
		if err := json.Unmarshal(env.Data, &st); err != nil {
			return
		}
		c.handler.OnStatus(st)
	case "test_result":
		if c.handler.OnTestResult == nil {
			return
		}
		var row guiapi.TestResult
		if err := json.Unmarshal(env.Data, &row); err != nil {
			return
		}
		c.handler.OnTestResult(row)
	}
}

func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = c.enc.Encode(Envelope{Type: MsgShutdown})
	c.conn.Close()
	select {
	case <-c.readDone:
	case <-time.After(clientCloseTimeout):
	}
	return c.readErr
}

func (c *Client) IsClosed() bool {
	return c.closed.Load()
}

func (c *Client) call(ctx context.Context, method string, params any, result any) error {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}

	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return errors.New("helper client closed")
	}
	id := c.nextID
	c.nextID++
	ch := make(chan Envelope, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if err := c.enc.Encode(Envelope{Type: MsgRequest, ID: id, Method: method, Params: rawParams}); err != nil {
		return err
	}

	select {
	case resp := <-ch:
		if resp.Error != "" {
			return errors.New(resp.Error)
		}
		if result == nil || len(resp.Result) == 0 {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	case <-ctx.Done():
		return ctx.Err()
	case <-c.readDone:
		if c.readErr != nil && !errors.Is(c.readErr, io.EOF) {
			return fmt.Errorf("helper disconnected: %w", c.readErr)
		}
		return errors.New("helper disconnected")
	}
}

func (c *Client) Start(ctx context.Context, cfg guiapi.ProxyConfig) error {
	return c.call(ctx, MethodStart, ConfigParams{Config: cfg}, nil)
}

func (c *Client) Stop(ctx context.Context) error {
	return c.call(ctx, MethodStop, nil, nil)
}

func (c *Client) RunTest(ctx context.Context, cfg guiapi.ProxyConfig) (guiapi.TestSummary, error) {
	var summary guiapi.TestSummary
	err := c.call(ctx, MethodRunTest, ConfigParams{Config: cfg}, &summary)
	return summary, err
}
