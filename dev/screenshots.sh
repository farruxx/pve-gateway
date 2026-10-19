#!/bin/sh
# Regenerate docs/screenshots/*.png from mock mode (needs Google Chrome and Node 22+).
#   dev/screenshots.sh            -> docs/screenshots
# Uses a throwaway mock state and port 8101, so a running ./dev.sh is not disturbed.
set -e
cd "$(dirname "$0")/.."
if curl -s -o /dev/null http://127.0.0.1:8101/; then
    echo "port 8101 is busy (an old mock server?) - stop it first, e.g.: pkill -f 'port 8101'"; exit 1
fi
TMP=$(mktemp -d)
trap 'kill $PID 2>/dev/null; rm -rf "$TMP"' EXIT
python3 pve-gateway.py --mock --config-dir "$TMP/state" apply >/dev/null 2>&1
python3 pve-gateway.py --mock --config-dir "$TMP/state" mock traffic >/dev/null
python3 pve-gateway.py --mock --config-dir "$TMP/state" mock traffic >/dev/null
python3 pve-gateway.py --mock --config-dir "$TMP/state" ui-allow 203.0.113.0/24 10.10.10.0/24 >/dev/null
python3 pve-gateway.py --mock --config-dir "$TMP/state" backup >/dev/null
python3 pve-gateway.py --mock --config-dir "$TMP/state" --port 8101 >"$TMP/server.log" 2>&1 &
PID=$!
sleep 1.5
PROFILE_DIR="$TMP/chrome" node dev/screenshots.mjs docs/screenshots
