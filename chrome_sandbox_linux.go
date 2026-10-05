//go:build linux

package browser

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

// Chromium computes this status from its renderer's namespace and seccomp
// layers. Check the native status page before exposing any agent capabilities;
// launch flags alone are not proof that the browser sandbox is active.
func requireChromeSandbox(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	if err := chromedp.Do(ctx, chromedp.Navigate("chrome://sandbox"), chromedp.WaitVisible(chromedp.CSS("#evaluation"))); err != nil {
		return ErrDenied
	}
	status, err := chromedp.Run(ctx, chromedp.Text(chromedp.CSS("#evaluation")))
	if err != nil || status != "You are adequately sandboxed." {
		return ErrDenied
	}
	return chromedp.Do(ctx, chromedp.Navigate("about:blank"))
}
