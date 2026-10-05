//go:build !linux

package browser

func RequireEncryptedVolume(string) error { return ErrDenied }
