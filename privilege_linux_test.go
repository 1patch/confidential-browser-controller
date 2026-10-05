//go:build linux

package browser

import (
	"os"
	"strings"
	"testing"
)

func TestLinuxContainerPrivileges(t *testing.T) {
	if os.Getuid() != 10001 {
		if os.Getenv("SURE_BROWSER_DROPPED_ROOT_PROOF") == "1" {
			t.Fatal("root startup did not drop UID")
		}
		t.Skip("container acceptance runs as UID 10001")
	}
	if e := RequireUnprivileged(); e != nil {
		t.Fatal("worker has capabilities or can gain privileges", e)
	}
	if os.Getenv("SURE_BROWSER_DROPPED_ROOT_PROOF") == "1" {
		data, err := os.ReadFile("/proc/self/status")
		if err != nil || !strings.Contains(string(data), "CapBnd:\t0000000000000000\n") {
			t.Fatal("root startup retained a capability bounding set")
		}
		groups, err := os.Getgroups()
		if err != nil || len(groups) != 0 || os.Getgid() != 10001 || os.Getegid() != 10001 {
			t.Fatal("root startup retained group authority")
		}
		if os.Getenv("SURE_BROWSER_LAUNCHER_SENTINEL") != "" {
			t.Fatal("launcher inherited unapproved environment")
		}
	}
}
