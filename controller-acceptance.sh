#!/bin/sh
set -eu
# Only the acceptance image replaces the post-drop executable with this script.
export SURE_BROWSER_MEMORY_PROOF=1
export SURE_BROWSER_DROPPED_ROOT_PROOF=1
exec /usr/local/bin/browser.test "$@"
