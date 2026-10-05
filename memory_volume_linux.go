//go:build linux

package browser

import (
	"os"
	"path/filepath"
	"strings"
)

// RequireMemoryVolume rejects ordinary disks and enabled swap. Object mode keeps
// browser plaintext in enclave RAM and uploads only authenticated ciphertext.
func RequireMemoryVolume(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, " \t\n\\") {
		return ErrInvalid
	}
	swaps, err := os.ReadFile("/proc/swaps")
	if err != nil || len(strings.Split(strings.TrimSpace(string(swaps)), "\n")) != 1 {
		return ErrDenied
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ErrDenied
	}
	for _, line := range strings.Split(string(mounts), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 3 || left[4] != root {
			continue
		}
		if right[0] != "tmpfs" {
			return ErrDenied
		}
		opts := "," + left[5] + ","
		for _, required := range []string{"rw", "nosuid", "nodev", "noexec"} {
			if !strings.Contains(opts, ","+required+",") {
				return ErrDenied
			}
		}
		return nil
	}
	return ErrDenied
}
