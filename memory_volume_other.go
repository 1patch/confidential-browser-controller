//go:build !linux

package browser

func RequireMemoryVolume(string) error { return ErrDenied }
