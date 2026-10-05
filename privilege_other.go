//go:build !linux

package browser

func RequireUnprivileged() error { return ErrDenied }
