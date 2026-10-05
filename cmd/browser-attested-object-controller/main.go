package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	browser "github.com/1patch/confidential-browser-controller"
)

func run() error {
	const root = "/workspace"
	if browser.RequireUnprivileged() != nil || browser.RequireMemoryVolume(root) != nil {
		return browser.ErrDenied
	}
	encoded := os.Getenv("BROWSER_CONTROLLER_BOOTSTRAP_PUBLIC_KEY")
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return browser.ErrDenied
	}
	for _, name := range []string{"BROWSER_OBJECT_CONTROLLER_LOCATION", "BROWSER_OBJECT_BOOTSTRAP", "BROWSER_BOOTSTRAP", "BROWSER_CONTROLLER_BOOTSTRAP"} {
		if os.Getenv(name) != "" {
			return browser.ErrDenied
		}
	}
	unlock, err := browser.LockDirectory(root)
	if err != nil {
		return err
	}
	defer unlock()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	gate, err := browser.NewControllerBootGate(ctx, ed25519.PublicKey(key))
	if err != nil {
		return err
	}
	return browser.ServeControllerBootGate(ctx, ":8080", gate)
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "browser controller startup, storage or recovery unavailable")
		os.Exit(1)
	}
}
