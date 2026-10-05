package browser

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// EgressProxy accepts HTTPS CONNECT only, resolves once and dials that exact
// public IP. Redirects, subresources and websocket handshakes use the same gate.
// Chromium must be configured with this proxy and no bypass list.
type EgressProxy struct {
	Policy   NetworkPolicy
	Resolver *net.Resolver
}

func (p EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.URL.User != nil {
		http.Error(w, "denied", 403)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" || p.Policy.CheckURL("https://"+r.Host) != nil {
		http.Error(w, "denied", 403)
		return
	}
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ips, err := publicAddresses(ctx, resolver, host)
	if err != nil {
		http.Error(w, "denied", 403)
		return
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
	if err != nil {
		http.Error(w, "unavailable", 502)
		return
	}
	defer conn.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unavailable", 500)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Minute))
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() { io.Copy(conn, rw); conn.Close(); close(done) }()
	io.Copy(client, conn)
	client.Close()
	<-done
}

func startProxy(policy NetworkPolicy) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, ErrUnavailable
	}
	server := &http.Server{Handler: EgressProxy{Policy: policy}, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	go server.Serve(ln)
	return "http://" + strings.TrimSpace(ln.Addr().String()), func() { server.Close() }, nil
}
