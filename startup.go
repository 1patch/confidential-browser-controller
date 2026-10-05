package browser

import (
	"context"
	"errors"
	"strings"
)

// Startup diagnostics are finite labels, never provider errors, paths or data.
// They let the operator locate a failed confidential boot without debug access.
type startupError struct {
	stage string
	cause error
}

func (e startupError) Error() string { return e.stage }
func (e startupError) Unwrap() error { return e.cause }

func startupFailure(stage string, err error) error {
	var failure startupError
	if errors.As(err, &failure) {
		return failure
	}
	return startupError{stage: stage, cause: err}
}

func startupFailureCode(err error) string {
	var failure startupError
	if errors.As(err, &failure) && validStartupFailure(failure.stage) {
		return failure.stage
	}
	return "initialization"
}

func chromeLaunchFailure(err error) error {
	code := "chromium-launch"
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		code = "chromium-launch-timeout"
	case strings.Contains(err.Error(), "No usable sandbox"), strings.Contains(err.Error(), "Failed to move to new namespace"):
		code = "chromium-namespace"
	}
	return startupFailure(code, err)
}

func validStartupFailure(code string) bool {
	switch code {
	case "initialization", "storage-identity", "profile-binding", "profile-open",
		"credentials-read", "chromium-launch", "chromium-launch-timeout", "chromium-namespace",
		"chromium-sandbox", "chromium-download-policy",
		"session-restore", "credential-install", "profile-checkpoint":
		return true
	}
	return false
}
