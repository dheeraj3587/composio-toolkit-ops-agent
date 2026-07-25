#!/bin/sh
# Browser-service entrypoint.
#
# Starts the interactive-HITL display stack ONLY when it is explicitly enabled,
# then execs the API server. Two properties matter here:
#
#   1. Interactive remote control is off by default. With
#      BROWSER_INTERACTIVE_HITL_ENABLED unset/false, no Xvfb, no window manager
#      and no x11vnc are started at all, so the dangerous surface does not exist.
#   2. x11vnc binds to LOOPBACK inside this container (-localhost) and the
#      container publishes no port. The only path in is the authenticated
#      WebSocket relay in browser_service.novnc, which verifies a signed,
#      session-bound, owner-bound, short-lived grant before connecting.
#
# `exec` at the end keeps uvicorn as PID 1's direct child so Compose's `init: true`
# reaps Chromium zombies and signals reach the server.

set -eu

DISPLAY_NUM="${BROWSER_DISPLAY_NUM:-99}"
SCREEN_GEOMETRY="${BROWSER_SCREEN_GEOMETRY:-1280x1024x24}"
VNC_PORT="${BROWSER_VNC_PORT:-5900}"

is_enabled() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1 | true | yes | on) return 0 ;;
        *) return 1 ;;
    esac
}

if is_enabled "${BROWSER_INTERACTIVE_HITL_ENABLED:-false}"; then
    echo "browser-service: interactive HITL enabled, starting display stack" >&2

    # Virtual framebuffer: Chromium can then run headful, which is what makes a
    # human handoff (CAPTCHA, account chooser, MFA) actually solvable.
    Xvfb ":${DISPLAY_NUM}" -screen 0 "${SCREEN_GEOMETRY}" -nolisten tcp &
    export DISPLAY=":${DISPLAY_NUM}"

    # Wait for the X socket rather than sleeping blindly.
    i=0
    while [ ! -e "/tmp/.X11-unix/X${DISPLAY_NUM}" ]; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then
            echo "browser-service: Xvfb failed to start" >&2
            exit 1
        fi
        sleep 0.1
    done

    # A minimal window manager so dialogs and popups are placed sanely.
    fluxbox >/dev/null 2>&1 &

    # -localhost is the load-bearing flag: x11vnc accepts connections only from
    # inside this container, so there is no raw public VNC port. -nopw is safe
    # ONLY because of that binding plus the authenticated relay in front of it;
    # a VNC password here would be a second secret with no added protection.
    x11vnc \
        -display ":${DISPLAY_NUM}" \
        -rfbport "${VNC_PORT}" \
        -localhost \
        -nopw \
        -shared \
        -forever \
        -noxdamage \
        -quiet \
        >/dev/null 2>&1 &
else
    echo "browser-service: interactive HITL disabled, headless only" >&2
fi

exec "$@"
