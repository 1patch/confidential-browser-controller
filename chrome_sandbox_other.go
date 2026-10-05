//go:build !linux

package browser

import "context"

// Local macOS acceptance uses Chrome's native sandbox. Production entrypoints
// independently reject non-Linux hosts before constructing a browser worker.
func requireChromeSandbox(context.Context) error { return nil }
