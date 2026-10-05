//go:build linux

package browser

import (
	"os"
	"strings"
)

// SYS_ADMIN and SYS_CHROOT in the bounding set permit Chromium's namespace
// setup and chroot syscalls through Docker's default seccomp profile. Neither
// capability may be effective, permitted or ambient in the worker's namespace.
func RequireUnprivileged() error {
	if os.Getuid() != 10001 || os.Geteuid() != 10001 {
		return ErrDenied
	}
	data, e := os.ReadFile("/proc/self/status")
	if e != nil {
		return ErrDenied
	}
	found := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Fields(line)
		if len(p) == 2 {
			found[p[0]] = p[1]
		}
	}
	for _, key := range []string{"CapEff:", "CapPrm:", "CapAmb:", "CapInh:"} {
		if found[key] != "0000000000000000" {
			return ErrDenied
		}
	}
	if found["NoNewPrivs:"] != "1" {
		return ErrDenied
	}
	if found["CapBnd:"] != "0000000000000000" && found["CapBnd:"] != "0000000000240000" {
		return ErrDenied
	}
	return nil
}
