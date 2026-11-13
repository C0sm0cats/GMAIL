#!/usr/bin/env sh
set -eu

# Follow symlinks (e.g. ~/.local/bin/savegmail) to the real script, so the
# .venv and savegmail.py are those of the project. Plain readlink, not -f:
# macOS's readlink has no -f before macOS 12.3.
script=$0
while [ -L "$script" ]; do
    target=$(readlink -- "$script")
    case $target in
        /*) script=$target ;;
        *) script=$(dirname -- "$script")/$target ;;
    esac
done
script_dir=$(CDPATH= cd -- "$(dirname -- "$script")" && pwd)

# Python 3.9 and 3.10 are end-of-life: their dependencies (requests, urllib3,
# google-api-core) no longer get security fixes there.
min_python='import sys; sys.exit(sys.version_info < (3, 11))'

# (Re)create the .venv when it has no working pip: missing, left half-made by a
# failed or interrupted creation (no python3-venv on Debian/Ubuntu), or built
# for a Python version the system no longer provides; or when it was built
# with a Python older than 3.11.
if ! "$script_dir/.venv/bin/python" -m pip --version >/dev/null 2>&1 ||
    ! "$script_dir/.venv/bin/python" -c "$min_python" >/dev/null 2>&1; then
    python=$(command -v python3 || command -v python) || {
        echo "run-savegmail.sh: Python 3.11 or newer is required (no python3 or python command found)" >&2
        exit 1
    }
    if ! "$python" -c "$min_python" >/dev/null 2>&1; then
        echo "run-savegmail.sh: Python 3.11 or newer is required ($python is older)" >&2
        exit 1
    fi
    "$python" -m venv --clear "$script_dir/.venv"
fi

# Upgrade the dependencies at most once a week (eager, so indirect ones such as
# certifi and oauthlib follow); an offline launch keeps the installed versions.
# No retries and a short timeout: offline, pip would otherwise retry every
# request for minutes before the launcher goes on.
stamp="$script_dir/.venv/.savegmail-upgraded"
if [ -z "$(find "$stamp" -mtime -7 2>/dev/null)" ]; then
    if "$script_dir/.venv/bin/python" -m pip install --quiet --retries 0 --timeout 10 --upgrade --upgrade-strategy eager \
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

chromium_check='from playwright.sync_api import sync_playwright; p = sync_playwright().start(); browser = p.chromium.launch(headless=True); browser.close(); p.stop()'
if ! "$script_dir/.venv/bin/python" -c "$chromium_check" >/dev/null 2>&1; then
    "$script_dir/.venv/bin/python" -m playwright install chromium
    # Installed but still not starting: usually system libraries missing (minimal Debian/Ubuntu,
    # WSL, containers). The list still works for d, e, * ...; saving and previews will not.
    if ! "$script_dir/.venv/bin/python" -c "$chromium_check" >/dev/null 2>&1; then
        echo "run-savegmail.sh: Chromium does not start (missing system libraries?); saving and previews will fail. On Debian/Ubuntu: sudo $script_dir/.venv/bin/python -m playwright install-deps chromium" >&2
    fi
fi

exec "$script_dir/.venv/bin/python" "$script_dir/savegmail.py" "$@"
