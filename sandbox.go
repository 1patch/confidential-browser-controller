package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fastschema/qjs"
)

// Sandbox never reuses a JS heap across requests or owners. qjs mounts its CWD;
// point it at a nonexistent child of a private empty directory, so WASI has no
// accessible filesystem, never the service or browser workspace.
type Sandbox struct {
	Safety  Safety
	Timeout time.Duration
}

func (s Sandbox) Execute(parent context.Context, owner, code string, driver Driver) (out RunResult, err error) {
	if s.Safety == nil || driver == nil || !identifier.MatchString(owner) || len(code) == 0 || len(code) > MaxCode {
		return out, ErrInvalid
	}
	deadline := s.Timeout
	if deadline <= 0 || deadline > ExecutionTimeout {
		deadline = ExecutionTimeout
	}
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	digest := sha256.Sum256([]byte(code))
	out.ProgramHash = hex.EncodeToString(digest[:])
	out.Safety = "stub-v1"
	if !s.Safety.Program(ctx, owner, code).Allow {
		return out, ErrDenied
	}
	dir, e := os.MkdirTemp("", "sure-wasm-")
	if e != nil {
		return out, ErrUnavailable
	}
	defer os.RemoveAll(dir)
	// qjs panics on a closed WASM context. Never forward its errors, which may
	// contain attacker-controlled source, observations or interpreter internals.
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	rt, e := qjs.New(qjs.Option{Context: ctx, CWD: filepath.Join(dir, "unmounted"), CloseOnContextDone: true, MemoryLimit: 32 << 20, MaxStackSize: 512 << 10, MaxExecutionTime: int(deadline.Milliseconds()), Stdout: io.Discard, Stderr: io.Discard})
	if e != nil {
		return out, ErrUnavailable
	}
	defer func() { defer func() { recover() }(); rt.Close() }()
	js := rt.Context()
	// Compile the whole user program before binding any effectful host function.
	// Serialize inside the JS heap. The binding's direct JSONStringify helper
	// returns an invalid short string for some otherwise valid observations.
	// Returning a JS string also gives one explicit, bounded wire format.
	source := "(async () => { const encode = JSON.stringify; return encode(await (async () => {\n\"use strict\";\n" + code + "\n})() ?? null); })()"
	if _, e = js.Compile("agent.js", qjs.Code(source)); e != nil {
		return out, ErrInvalid
	}
	js.SetFunc("__browserAction", func(this *qjs.This) (*qjs.Value, error) {
		if ctx.Err() != nil || len(this.Args()) != 1 || !this.Args()[0].IsString() {
			return nil, ErrDenied
		}
		raw := this.Args()[0].String()
		if len(raw) > 16<<10 {
			return nil, ErrInvalid
		}
		var action Action
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&action) != nil {
			return nil, ErrInvalid
		}
		if out.Actions >= MaxActions {
			return nil, ErrDenied
		}
		out.Actions++
		// Inspect the selected persistent tab, not a URL cached from a different
		// tab or lost when a fresh WASM heap begins the next tool call.
		currentURL := ""
		if action.Op != "navigate" && action.Op != "newTab" && action.Op != "tabs" {
			var e error
			currentURL, e = driver.CurrentURL(ctx, action.Tab)
			if e != nil {
				return nil, ErrDenied
			}
		}
		decision := s.Safety.Action(ctx, ActionContext{Owner: owner, ProgramHash: out.ProgramHash, Sequence: out.Actions, CurrentURL: currentURL, Action: action})
		if !decision.Allow {
			return nil, ErrDenied
		}
		result, e := driver.Do(ctx, action)
		if e != nil {
			return nil, ErrDenied
		}
		encoded, e := json.Marshal(result)
		if e != nil || len(encoded) > MaxOutput {
			return nil, ErrUnavailable
		}
		return this.Context().NewString(string(encoded)), nil
	})
	bootstrap := `(() => {
  const call = __browserAction; delete globalThis.__browserAction;
  const invoke = (op,args={}) => JSON.parse(call(JSON.stringify({...args,op})));
  const api = Object.create(null);
  for (const op of ["navigate","newTab","snapshot","screenshot","tabs","closeTab","click","fill","press","scroll"])
    Object.defineProperty(api,op,{value:(args={})=>invoke(op,args),enumerable:true});
  Object.defineProperty(globalThis,"browser",{value:Object.freeze(api),writable:false,configurable:false});
})()`
	value, e := js.Eval("bootstrap.js", qjs.Code(bootstrap))
	if e != nil {
		return out, ErrUnavailable
	}
	value.Free()
	result, e := js.Eval("agent.js", qjs.Code(source))
	if e != nil {
		return out, ErrDenied
	}
	defer result.Free()
	value = result
	if result.IsPromise() {
		value, e = result.Await()
		if e != nil {
			return out, ErrDenied
		}
		defer value.Free()
	}
	if ctx.Err() != nil {
		return out, ErrDenied
	}
	if !value.IsString() {
		return out, ErrInvalid
	}
	encoded := value.String()
	if len(encoded) > MaxOutput || !json.Valid([]byte(encoded)) {
		return out, ErrInvalid
	}
	out.Value = json.RawMessage(encoded)
	return out, nil
}
