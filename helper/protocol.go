package helper

import (
	"encoding/json"
	"fmt"

	"sni-spoofing-go/guiapi"
)

const (
	MsgAuth      = "auth"
	MsgAuthOK    = "auth_ok"
	MsgAuthFail  = "auth_fail"
	MsgRequest   = "request"
	MsgResponse  = "response"
	MsgEvent     = "event"
	MsgShutdown  = "shutdown"
)

const (
	MethodStart   = "start"
	MethodStop    = "stop"
	MethodRunTest = "run_test"
)

type Envelope struct {
	Type    string          `json:"type"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Name    string          `json:"name,omitempty"`
	Token   string          `json:"token,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Message string          `json:"message,omitempty"`
}

type ConfigParams struct {
	Config guiapi.ProxyConfig `json:"config"`
}

func rpcError(id int, err error) Envelope {
	return Envelope{Type: MsgResponse, ID: id, Error: err.Error()}
}

func rpcOK(id int, result any) (Envelope, error) {
	var raw json.RawMessage
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return Envelope{}, err
		}
		raw = b
	}
	return Envelope{Type: MsgResponse, ID: id, Result: raw}, nil
}

func event(name string, data any) (Envelope, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal event %q: %w", name, err)
	}
	return Envelope{Type: MsgEvent, Name: name, Data: b}, nil
}
