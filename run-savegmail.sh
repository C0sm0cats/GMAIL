#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -x "$script_dir/.venv/bin/python" ]; then
    python -m venv "$script_dir/.venv"
fi

# Upgrade the dependencies at most once a week (eager, so indirect ones such as
# certifi and oauthlib follow); an offline launch keeps the installed versions.
stamp="$script_dir/.venv/.savegmail-upgraded"
if [ -z "$(find "$stamp" -mtime -7 2>/dev/null)" ]; then
    if "$script_dir/.venv/bin/python" -m pip install --quiet --upgrade --upgrade-strategy eager \
        playwright \
        prompt_toolkit \
        rich \
        google-api-python-client \
        google-auth \
        google-auth-oauthlib \
        tzlocal \
        certifi; then
        touch "$stamp"
    elif ! "$script_dir/.venv/bin/python" -c 'import googleapiclient, google_auth_oauthlib, playwright, prompt_toolkit, rich, tzlocal' >/dev/null 2>&1; then
        exit 1
    fi
fi

export PATH="$script_dir/.venv/bin:$PATH"
export PLAYWRIGHT_BROWSERS_PATH=0

if ! "$script_dir/.venv/bin/python" -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(headless=True); browser.close(); p.stop()' >/dev/null 2>&1; then
    "$script_dir/.venv/bin/python" -m playwright install chromium
fi

exec "$script_dir/.venv/bin/python" "$script_dir/savegmail.py" "$@"
