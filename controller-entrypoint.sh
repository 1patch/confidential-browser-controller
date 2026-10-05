#!/bin/sh
set -eu
# Measured startup only. Drop every privilege and inherited variable before the
# listener, object client, cloud API client or runtime credential exists.
test "$(/usr/bin/id -u)" = 0
exec /usr/bin/setpriv \
  --reuid=10001 --regid=10001 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  /usr/bin/env -i HOME=/workspace PATH=/usr/local/bin:/usr/bin:/bin \
  BROWSER_CONTROLLER_BOOTSTRAP_PUBLIC_KEY="${BROWSER_CONTROLLER_BOOTSTRAP_PUBLIC_KEY:-}" \
  /usr/local/bin/browser-attested-object-controller "$@"
