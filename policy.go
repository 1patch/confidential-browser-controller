package browser

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

// StubSafety is deliberately deterministic. It is not a trained safety model.
// The model may later veto an action; it must never expand these capabilities.
type StubSafety struct {
	Policy      NetworkPolicy
	AllowWrites bool
}

func (s StubSafety) Program(ctx context.Context, owner, code string) Decision {
	return Decision{ctx.Err() == nil && identifier.MatchString(owner) && len(code) > 0 && len(code) <= MaxCode, "stub-v1", "bounded-program"}
}

func (s StubSafety) Action(ctx context.Context, a ActionContext) Decision {
	deny := Decision{false, "stub-v1", "capability-denied"}
	if ctx.Err() != nil || a.Sequence < 1 || a.Sequence > MaxActions {
		return deny
	}
	switch a.Action.Op {
	case "navigate", "newTab":
		if s.Policy.CheckURL(a.Action.URL) != nil {
			return deny
		}
	case "snapshot", "screenshot", "tabs", "closeTab":
	case "click", "fill", "press", "scroll":
		if !s.AllowWrites || s.Policy.CheckURL(a.CurrentURL) != nil {
			return deny
		}
	default:
		return deny
	}
	return Decision{true, "stub-v1", "explicit-capability"}
}

// NetworkPolicy uses exact HTTPS origins, not suffixes or model-controlled
// regular expressions. The network proxy also pins public DNS resolutions.
type NetworkPolicy struct {
	Origins []string `json:"origins"`
}

func (p NetworkPolicy) CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 8192 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(raw, "\r\n\x00\\") {
		return ErrDenied
	}
	if u.Port() != "" && u.Port() != "443" {
		return ErrDenied
	}
	if strings.HasSuffix(u.Hostname(), ".") || strings.Contains(u.Hostname(), "%") {
		return ErrDenied
	}
	origin := "https://" + strings.ToLower(u.Hostname())
	for _, allowed := range p.Origins {
		if origin == allowed {
			return nil
		}
	}
	return ErrDenied
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "2002::/16"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

func publicAddresses(ctx context.Context, resolver *net.Resolver, host string) ([]netip.Addr, error) {
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, ErrDenied
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, ErrDenied
		}
	}
	return ips, nil
}
