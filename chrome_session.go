package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"golang.org/x/net/publicsuffix"
)

const maxSessionBytes = 8 << 20

// This interface is private Go lifecycle plumbing. It is deliberately absent
// from Driver, Action, the WASM host function and every HTTP agent route.
type privateBrowserSession interface {
	exportSession(context.Context) ([]byte, error)
	restoreSession(context.Context, []byte) error
}
type chromeSession struct {
	Version int               `json:"version"`
	Cookies []*network.Cookie `json:"cookies"`
}

func cookieParameters(cookie *network.Cookie, policy NetworkPolicy) (*network.CookieParam, error) {
	if cookie == nil || !cookie.Session || cookie.PartitionKeyOpaque || len(cookie.Name) > 256 || len(cookie.Value) > 8192 || len(cookie.Path) > 1024 || !strings.HasPrefix(cookie.Path, "/") || cookie.SourceScheme != network.CookieSourceSchemeSecure || (cookie.SourcePort != -1 && cookie.SourcePort != 443) {
		return nil, ErrDenied
	}
	if (&http.Cookie{Name: cookie.Name, Value: cookie.Value, Domain: cookie.Domain, Path: cookie.Path}).Valid() != nil {
		return nil, ErrDenied
	}
	domain := strings.TrimPrefix(cookie.Domain, ".")
	if domain == "" || domain != strings.ToLower(domain) {
		return nil, ErrDenied
	}
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return nil, ErrDenied
	}
	allowed := ""
	for _, origin := range policy.Origins {
		host := strings.TrimPrefix(origin, "https://")
		if host == domain || strings.HasPrefix(cookie.Domain, ".") && strings.HasSuffix(host, "."+domain) {
			allowed = origin
			break
		}
	}
	if allowed == "" {
		return nil, ErrDenied
	}
	if p := cookie.PartitionKey; p != nil {
		site := strings.TrimPrefix(p.TopLevelSite, "https://")
		if site == p.TopLevelSite || strings.ContainsAny(site, "/:@?#%\\") {
			return nil, ErrDenied
		}
		registrable, err := publicsuffix.EffectiveTLDPlusOne(site)
		if err != nil || registrable != site {
			return nil, ErrDenied
		}
		found := false
		for _, origin := range policy.Origins {
			host := strings.TrimPrefix(origin, "https://")
			if host == site || strings.HasSuffix(host, "."+site) {
				found = true
			}
		}
		if !found {
			return nil, ErrDenied
		}
	}
	param := &network.CookieParam{Name: cookie.Name, Value: cookie.Value, URL: allowed + cookie.Path, Path: cookie.Path, Secure: cookie.Secure, HTTPOnly: cookie.HTTPOnly, SameSite: cookie.SameSite, Priority: cookie.Priority, SourceScheme: cookie.SourceScheme, SourcePort: cookie.SourcePort, PartitionKey: cookie.PartitionKey}
	// Host-only cookies use URL and omit Domain. Supplying a Domain attribute
	// would broaden authentication to subdomains during restoration.
	if strings.HasPrefix(cookie.Domain, ".") {
		param.Domain = cookie.Domain
	}
	return param, nil
}

func (c *Chrome) exportSession(parent context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || parent.Err() != nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(c.root, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	result, err := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (storage.GetCookiesResult, error) {
		return cdp.Call(ctx, t, storage.GetCookies, storage.GetCookiesParams{})
	})
	if err != nil || len(result.Cookies) > 4096 {
		return nil, ErrUnavailable
	}
	saved := chromeSession{Version: 1, Cookies: []*network.Cookie{}}
	for _, cookie := range result.Cookies {
		if cookie == nil {
			return nil, ErrDenied
		}
		if !cookie.Session {
			continue
		}
		if _, err = cookieParameters(cookie, c.cfg.Policy); err != nil {
			return nil, err
		}
		saved.Cookies = append(saved.Cookies, cookie)
	}
	data, err := json.Marshal(saved)
	if err != nil || len(data) > maxSessionBytes {
		return nil, ErrCapacity
	}
	return data, nil
}

func (c *Chrome) restoreSession(parent context.Context, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || parent.Err() != nil || len(data) > maxSessionBytes {
		return ErrDenied
	}
	var saved chromeSession
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&saved) != nil || d.Decode(new(any)) != io.EOF || saved.Version != 1 || len(saved.Cookies) > 4096 {
		return ErrDenied
	}
	params := make([]*network.CookieParam, 0, len(saved.Cookies))
	for _, cookie := range saved.Cookies {
		p, err := cookieParameters(cookie, c.cfg.Policy)
		if err != nil {
			return err
		}
		params = append(params, p)
	}
	if len(params) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.root, 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	_, err := chromedp.Run(ctx, func(ctx context.Context, t *chromedp.Target) (cdp.Empty, error) {
		return cdp.Call(ctx, t, storage.SetCookies, storage.SetCookiesParams{Cookies: params})
	})
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
