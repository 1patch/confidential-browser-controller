package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/accessibility"
	cdpbrowser "github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type ChromeConfig struct {
	Executable       string
	ProfileDirectory string
	Policy           NetworkPolicy
	// Only injected by same-package tests. No production config or agent input
	// can bypass TLS validation, the egress proxy or the Chromium sandbox.
	testOptions []chromedp.ExecAllocatorOption
}
type chromeTab struct {
	ctx    context.Context
	cancel context.CancelFunc
}
type Chrome struct {
	mu          sync.Mutex
	cfg         ChromeConfig
	root        context.Context
	cancel      context.CancelFunc
	stopProxy   func()
	tabs        map[string]chromeTab
	next        int
	refs        map[string]map[string]cdp.BackendNodeID
	observation int
	closed      bool
	closeErr    error
}

func NewChrome(ctx context.Context, cfg ChromeConfig) (*Chrome, error) {
	if cfg.ProfileDirectory == "" || !filepath.IsAbs(cfg.ProfileDirectory) || len(cfg.Policy.Origins) == 0 {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(cfg.ProfileDirectory, 0700); err != nil {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(cfg.ProfileDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	proxy, stopProxy, err := startProxy(cfg.Policy)
	if err != nil {
		return nil, err
	}
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.UserDataDir(cfg.ProfileDirectory), chromedp.WindowSize(1280, 800), chromedp.ProxyServer(proxy), chromedp.NoInheritEnv,
		chromedp.Env("HOME="+cfg.ProfileDirectory, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"),
		chromedp.Flag("remote-debugging-pipe", true),
		chromedp.Flag("proxy-bypass-list", "<-loopback>"), chromedp.Flag("disable-quic", true),
		chromedp.Flag("force-webrtc-ip-handling-policy", "disable_non_proxied_udp"),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"),
		chromedp.Flag("disable-extensions", true), chromedp.Flag("disable-sync", true), chromedp.Flag("no-sandbox", false))
	if cfg.Executable != "" {
		opts = append(opts, chromedp.ExecPath(cfg.Executable))
	}
	opts = append(opts, cfg.testOptions...)
	allocator, stopAllocator := chromedp.NewExecAllocator(ctx, opts...)
	root, stopRoot := chromedp.NewContext(allocator)
	c := &Chrome{cfg: cfg, root: root, tabs: map[string]chromeTab{}, refs: map[string]map[string]cdp.BackendNodeID{}, stopProxy: stopProxy, cancel: func() { stopRoot(); stopAllocator() }}
	if err = chromedp.Do(root); err != nil {
		c.cancel()
		stopProxy()
		return nil, chromeLaunchFailure(err)
	}
	if err = requireChromeSandbox(root); err != nil {
		c.cancel()
		stopProxy()
		return nil, startupFailure("chromium-sandbox", err)
	}
	if _, err = chromedp.Run(root, func(ctx context.Context, t *chromedp.Target) (cdp.Empty, error) {
		return cdp.Call(ctx, t, cdpbrowser.SetDownloadBehavior, cdpbrowser.SetDownloadBehaviorParams{Behavior: cdpbrowser.SetDownloadBehaviorBehaviorDeny})
	}); err != nil {
		c.cancel()
		stopProxy()
		return nil, startupFailure("chromium-download-policy", err)
	}
	c.tabs["tab-1"] = chromeTab{root, func() {}}
	c.next = 1
	return c, nil
}

func (c *Chrome) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	c.closed = true
	stop := context.AfterFunc(ctx, c.cancel)
	defer stop()
	err := chromedp.Cancel(c.root)
	c.cancel()
	c.stopProxy()
	if err != nil {
		c.closeErr = ErrUncertain
	}
	return c.closeErr
}

func (c *Chrome) CurrentURL(parent context.Context, id string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || parent.Err() != nil {
		return "", ErrDenied
	}
	if id == "" {
		id = "tab-1"
	}
	tab, ok := c.tabs[id]
	if !ok {
		return "", ErrDenied
	}
	ctx, cancel := context.WithTimeout(tab.ctx, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	url, err := chromedp.Run(ctx, chromedp.Location())
	if err != nil {
		return "", ErrUnavailable
	}
	return url, nil
}

func (c *Chrome) Do(parent context.Context, a Action) (Observation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return Observation{}, ErrUnavailable
	}
	if parent.Err() != nil {
		return Observation{}, ErrDenied
	}
	if len(a.Selector) > 1024 || len(a.Text) > 8192 || len(a.Key) > 32 || len(a.Ref) > 80 || a.Ref != "" && a.Selector != "" {
		return Observation{}, ErrInvalid
	}
	if a.Op == "newTab" {
		if len(c.tabs) >= 8 || c.cfg.Policy.CheckURL(a.URL) != nil {
			return Observation{}, ErrDenied
		}
		ctx, cancel := chromedp.NewContext(c.root)
		// Initialize the CDP target on its lifetime context. Initializing it on
		// the short action deadline would kill its event reader after navigation.
		stopParent := context.AfterFunc(parent, cancel)
		timer := time.AfterFunc(10*time.Second, cancel)
		err := chromedp.Do(ctx)
		timer.Stop()
		stopParent()
		if err != nil {
			cancel()
			return Observation{}, ErrUnavailable
		}
		c.next++
		id := fmt.Sprintf("tab-%d", c.next)
		c.tabs[id] = chromeTab{ctx, cancel}
		a.Tab = id
		a.Op = "navigate"
	}
	if a.Op == "tabs" {
		result := Observation{}
		ids := make([]string, 0, len(c.tabs))
		for id := range c.tabs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			tab := c.tabs[id]
			ctx, cancel := context.WithTimeout(tab.ctx, 5*time.Second)
			stop := context.AfterFunc(parent, cancel)
			url, err := chromedp.Run(ctx, chromedp.Location())
			stop()
			cancel()
			if err != nil {
				return Observation{}, ErrUnavailable
			}
			if url != "about:blank" && c.cfg.Policy.CheckURL(url) != nil {
				continue
			}
			result.Tabs = append(result.Tabs, Observation{Tab: id, URL: url})
		}
		return result, nil
	}
	id := a.Tab
	if id == "" {
		id = "tab-1"
	}
	tab, ok := c.tabs[id]
	if !ok {
		return Observation{}, ErrDenied
	}
	// Closing a known secondary tab needs no access to its content. A failed
	// navigation may leave it blank or at a denied origin; it must stay closable.
	if a.Op == "closeTab" {
		if id == "tab-1" {
			return Observation{}, ErrDenied
		}
		tab.cancel()
		delete(c.tabs, id)
		delete(c.refs, id)
		return Observation{Tab: id}, nil
	}
	ctx, cancel := context.WithTimeout(tab.ctx, 20*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	if parent.Err() != nil {
		return Observation{}, ErrDenied
	}
	if a.Op == "navigate" {
		if c.cfg.Policy.CheckURL(a.URL) != nil {
			return Observation{}, ErrDenied
		}
		if err := chromedp.Do(ctx, chromedp.Navigate(a.URL)); err != nil {
			return Observation{}, ErrUncertain
		}
	}
	url, err := chromedp.Run(ctx, chromedp.Location())
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	if c.cfg.Policy.CheckURL(url) != nil {
		return Observation{}, ErrDenied
	}
	var effect chromedp.Action[chromedp.Void]
	var target chromedp.NodeIDs
	if a.Ref != "" {
		backend, known := c.refs[id][a.Ref]
		if !known || (a.Op != "click" && a.Op != "fill") {
			return Observation{}, ErrDenied
		}
		resolved, e := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (dom.PushNodesByBackendIDsToFrontendResult, error) {
			return cdp.Call(ctx, t, dom.PushNodesByBackendIDsToFrontend, dom.PushNodesByBackendIDsToFrontendParams{BackendNodeIDs: []cdp.BackendNodeID{backend}})
		})
		if e != nil || len(resolved.NodeIDs) != 1 || resolved.NodeIDs[0] == 0 {
			return Observation{}, ErrDenied
		}
		target = chromedp.NodeIDs(resolved.NodeIDs)
	}
	switch a.Op {
	case "navigate", "snapshot":
	case "click":
		if target != nil {
			effect = chromedp.Click(target)
		} else if a.Selector == "" {
			effect = chromedp.MouseClickXY(a.X, a.Y)
		} else {
			effect = chromedp.Click(chromedp.CSS(a.Selector))
		}
	case "fill":
		if target != nil {
			effect = fillText(target, a.Text)
		} else if a.Selector == "" {
			return Observation{}, ErrInvalid
		} else {
			effect = fillText(chromedp.CSS(a.Selector), a.Text)
		}
	case "press":
		keys := map[string]string{"Enter": "\r", "Tab": "\t", "Escape": "\u001b", "Backspace": "\b", "ArrowDown": "\ue015", "ArrowUp": "\ue013", "ArrowLeft": "\ue012", "ArrowRight": "\ue014"}
		key, ok := keys[a.Key]
		if !ok {
			return Observation{}, ErrDenied
		}
		effect = chromedp.KeyEvent(key)
	case "scroll":
		if a.X < -2000 || a.X > 2000 || a.Y < -2000 || a.Y > 2000 {
			return Observation{}, ErrInvalid
		}
		_, err = chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (cdp.Empty, error) {
			return cdp.Call(ctx, t, input.DispatchMouseEvent, input.DispatchMouseEventParams{Type: input.DispatchMouseEventTypeMouseWheel, X: 640, Y: 400, DeltaX: a.X, DeltaY: a.Y})
		})
	case "screenshot":
		shot, e := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (page.CaptureScreenshotResult, error) {
			return cdp.Call(ctx, t, page.CaptureScreenshot, page.CaptureScreenshotParams{Format: page.CaptureScreenshotFormatJpeg, Quality: new(int64(60)), CaptureBeyondViewport: new(false)})
		})
		if e != nil || len(shot.Data) > (MaxOutput-4096)*3/4 {
			return Observation{}, ErrUnavailable
		}
		return Observation{Tab: id, URL: url, Image: base64.StdEncoding.EncodeToString(shot.Data), MimeType: "image/jpeg"}, nil
	default:
		return Observation{}, ErrDenied
	}
	if effect != nil {
		err = chromedp.Do(ctx, effect)
	}
	if err != nil {
		return Observation{}, ErrUncertain
	}
	url, err = chromedp.Run(ctx, chromedp.Location())
	if err != nil || c.cfg.Policy.CheckURL(url) != nil {
		return Observation{}, ErrDenied
	}
	title, _ := chromedp.Run(ctx, chromedp.Title())
	tree, err := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (accessibility.GetFullAXTreeResult, error) {
		return cdp.Call(ctx, t, accessibility.GetFullAXTree, accessibility.GetFullAXTreeParams{})
	})
	if err != nil {
		return Observation{}, ErrUnavailable
	}
	var text strings.Builder
	c.observation++
	c.refs[id] = map[string]cdp.BackendNodeID{}
	for _, node := range tree.Nodes {
		if node.Ignored || node.Role == nil || node.Name == nil {
			continue
		}
		role := axString(node.Role.Value)
		name := axString(node.Name.Value)
		// Values are intentionally omitted: password/input values and browser
		// authentication state are not part of the observation capability.
		if role == "none" || role == "generic" {
			continue
		}
		if text.Len()+len(role)+len(name) > 48<<10 {
			break
		}
		ref := ""
		if node.BackendDOMNodeID != 0 && role != "StaticText" && role != "InlineTextBox" {
			ref = fmt.Sprintf("r%d-%d", c.observation, len(c.refs[id])+1)
			c.refs[id][ref] = node.BackendDOMNodeID
		}
		fmt.Fprintf(&text, "%s %s %s\n", ref, role, name)
	}
	return Observation{Tab: id, URL: url, Title: title, Text: text.String()}, nil
}

// Native editing events update controlled inputs as well as their DOM value.
// Never use SendKeys here: that helper treats file inputs as host-file uploads.
// InsertText receives literal data, not agent-supplied JavaScript or key chords.
func fillText[S chromedp.Selectable](selector S, text string) chromedp.Action[chromedp.Void] {
	return func(ctx context.Context, target *chromedp.Target) (chromedp.Void, error) {
		valid, err := chromedp.QueryAfter(selector, func(_ context.Context, _ *chromedp.Target, nodes []*chromedp.Node) (bool, error) {
			if len(nodes) != 1 {
				return false, ErrDenied
			}
			node := nodes[0]
			node.RLock()
			defer node.RUnlock()
			kind, editable := "text", false
			for i := 0; i+1 < len(node.Attributes); i += 2 {
				switch node.Attributes[i] {
				case "type":
					kind = strings.ToLower(node.Attributes[i+1])
				case "contenteditable":
					editable = node.Attributes[i+1] == "" || node.Attributes[i+1] == "true" || node.Attributes[i+1] == "plaintext-only"
				case "disabled", "readonly":
					return false, ErrDenied
				}
			}
			if node.NodeName == "TEXTAREA" || editable {
				return true, nil
			}
			return node.NodeName == "INPUT" && (kind == "text" || kind == "search" || kind == "tel" || kind == "url" || kind == "email" || kind == "password" || kind == "number"), nil
		})(ctx, target)
		if err != nil || !valid {
			return chromedp.Void{}, ErrDenied
		}
		if _, err = chromedp.Focus(selector)(ctx, target); err != nil {
			return chromedp.Void{}, err
		}
		if _, err = cdp.Call(ctx, target, input.DispatchKeyEvent, input.DispatchKeyEventParams{Type: input.DispatchKeyEventTypeKeyDown, Commands: []string{"selectAll", "deleteBackward"}}); err != nil {
			return chromedp.Void{}, err
		}
		_, err = cdp.Call(ctx, target, input.InsertText, input.InsertTextParams{Text: text})
		return chromedp.Void{}, err
	}
}

func axString(v json.RawMessage) string {
	var s string
	if json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}

// InstallCredential is a trusted operator capability, absent from the JS API.
// The secret never enters the DOM or JS heap; the site receives an HttpOnly,
// Secure, host-only cookie. The configured site itself must be trusted not to
// reflect its credentials into visible content.
func (c *Chrome) InstallCredential(parent context.Context, secret CookieCredential) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if secret.Validate(c.cfg.Policy) != nil {
		return ErrDenied
	}
	ctx, cancel := context.WithTimeout(c.root, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	_, err := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (cdp.Empty, error) {
		return cdp.Call(ctx, t, network.SetCookie, network.SetCookieParams{Name: secret.CookieName, Value: secret.Value, URL: secret.Origin + "/", Path: "/", Secure: new(true), HTTPOnly: new(true), SameSite: network.CookieSameSiteStrict})
	})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
