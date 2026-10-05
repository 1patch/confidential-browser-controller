package browser

import (
	"context"
	"encoding/json"
)

const MaxAgentMessage = 4 << 20

type AgentStep struct {
	ID        string          `json:"id"`
	Start     json.RawMessage `json:"start,omitempty"`
	Ack       uint64          `json:"ack"`
	Reply     json.RawMessage `json:"reply,omitempty"`
	Cancel    bool            `json:"cancel,omitempty"`
	Heartbeat bool            `json:"heartbeat,omitempty"`
}
type AgentEvent struct {
	Sequence uint64          `json:"sequence"`
	Message  json.RawMessage `json:"message"`
}

// AgentEndpoint is optional trusted application code. A browser-only worker has
// no endpoint, inference credential, Node runtime or application session code.
type AgentEndpoint interface {
	Step(context.Context, Principal, AgentStep) (AgentEvent, error)
	Close()
}
