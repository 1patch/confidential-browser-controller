//go:build linux

package browser

import (
	"os"
	"path/filepath"
	"strings"
)

// RequireEncryptedVolume refuses an ephemeral directory masquerading as the
// configured persistent mount. The measured CVM owns the dm-crypt setup.
func RequireEncryptedVolume(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, " \t\n\\") {
		return ErrInvalid
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ErrDenied
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[4] != root {
			continue
		}
		device := fields[2]
		if strings.ContainsAny(device, "/.") {
			return ErrDenied
		}
		// Tinfoil creates the mapping directly with dm ioctls, not cryptsetup;
		// it has no CRYPT-* UUID. This name is assigned by measured CVM code.
		name, err := os.ReadFile("/sys/dev/block/" + device + "/dm/name")
		if err != nil || strings.TrimSpace(string(name)) != "tinfoil-volume-"+filepath.Base(root) {
			return ErrDenied
		}
		return nil
	}
	return ErrDenied
}
