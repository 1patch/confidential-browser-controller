package browser

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

var (
	ErrDenied      = errors.New("browser operation denied")
	ErrInvalid     = errors.New("invalid browser request")
	ErrUnavailable = errors.New("browser unavailable")
	ErrUncertain   = errors.New("browser outcome uncertain; inspect before retrying")
	ErrCapacity    = errors.New("browser capacity unavailable")
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}$`)

// Principal is supplied by verified authentication, never the JavaScript body.
type Principal struct {
	Owner    string `json:"owner"`
	Audience string `json:"audience"`
	Expires  int64  `json:"expires"`
	ID       string `json:"id"`
	Scope    string `json:"scope"`
}

type ExecuteRequest struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

type Action struct {
	Op       string  `json:"op"`
	Tab      string  `json:"tab,omitempty"`
	URL      string  `json:"url,omitempty"`
	Selector string  `json:"selector,omitempty"`
	Ref      string  `json:"ref,omitempty"`
	Text     string  `json:"text,omitempty"`
	Key      string  `json:"key,omitempty"`
	X        float64 `json:"x,omitempty"`
	Y        float64 `json:"y,omitempty"`
}

type Observation struct {
	Tab      string        `json:"tab,omitempty"`
	URL      string        `json:"url,omitempty"`
	Title    string        `json:"title,omitempty"`
	Text     string        `json:"text,omitempty"`
	Image    string        `json:"image,omitempty"`
	MimeType string        `json:"mimeType,omitempty"`
	Tabs     []Observation `json:"tabs,omitempty"`
}

type ActionContext struct {
	Owner       string
	ProgramHash string
	Sequence    int
	CurrentURL  string
	Action      Action
}

type Decision struct {
	Allow  bool   `json:"allow"`
	Policy string `json:"policy"`
	Reason string `json:"reason"`
}

type Safety interface {
	Program(context.Context, string, string) Decision
	Action(context.Context, ActionContext) Decision
}

type Driver interface {
	CurrentURL(context.Context, string) (string, error)
	Do(context.Context, Action) (Observation, error)
	Close(context.Context) error
}

type RunResult struct {
	Value       json.RawMessage `json:"value"`
	Actions     int             `json:"actions"`
	ProgramHash string          `json:"programHash"`
	Safety      string          `json:"safety"`
}

const (
	MaxCode          = 32 << 10
	MaxOutput        = 256 << 10
	MaxActions       = 100
	ExecutionTimeout = 30 * time.Second
)
