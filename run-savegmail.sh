#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -x "$script_dir/.venv/bin/python" ]; then
    python -m venv "$script_dir/.venv"
fi

# Observed with the official pip bootstrap on 2026-05-22:
#   playwright 1.60.0
#   bundled Playwright driver Node v24.15.0
if ! "$script_dir/.venv/bin/python" -c 'import googleapiclient, google_auth_oauthlib, playwright, pytz, tzlocal' >/dev/null 2>&1; then
    "$script_dir/.venv/bin/python" -m pip install \
        playwright \
        google-api-python-client \
        google-auth \
        google-auth-oauthlib \
        pytz \
        tzlocal
fi

export PATH="$script_dir/.venv/bin:$PATH"
export PLAYWRIGHT_BROWSERS_PATH=0

if ! "$script_dir/.venv/bin/python" -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(headless=True); browser.close(); p.stop()' >/dev/null 2>&1; then
    "$script_dir/.venv/bin/python" -m playwright install chromium
fi

exec "$script_dir/.venv/bin/python" "$script_dir/savegmail.py" "$@"
