//go:build linux

package browser

import (
	"os"
	"testing"
)

func TestLinuxObjectMemoryVolume(t *testing.T) {
	if RequireMemoryVolume("/") == nil || RequireMemoryVolume(t.TempDir()) == nil || RequireMemoryVolume("relative") == nil {
		t.Fatal("ordinary directory passed the memory mount boundary")
	}
	if os.Getenv("SURE_BROWSER_MEMORY_PROOF") != "1" {
		t.Skip("container acceptance supplies a private /workspace tmpfs")
	}
	if os.Getuid() != 10001 || RequireUnprivileged() != nil {
		t.Fatal("object worker privilege boundary")
	}
	if err := RequireMemoryVolume("/workspace"); err != nil {
		t.Fatal("private no-swap RAM filesystem", err)
	}
}
