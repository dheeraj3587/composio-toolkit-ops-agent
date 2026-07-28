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
# A distinct loopback listener enforces view-only access inside x11vnc itself.
# Keep ten ports between the defaults because the display pool supports at most
# ten slots (control 5900-5909, view-only 5910-5919).
VIEW_VNC_PORT="${BROWSER_VIEW_ONLY_VNC_PORT:-$((VNC_PORT + 10))}"

is_enabled() {
    case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
        1 | true | yes | on) return 0 ;;
        *) return 1 ;;
    esac
}

# Chromium needs a WRITABLE HOME even when it persists no profile: a HEADFUL
# startup touches $HOME for GTK/dconf, fontconfig and NSS state. The image WORKDIR
# (/app) sits on the read-only root filesystem, so a headful launch died instantly
# with SIGTRAP, surfaced by Playwright as "Target page, context or browser has been
# closed", while HEADLESS - which touches none of that - kept working. That is why
# the readiness probe stayed green while every real session failed to start.
# Point HOME and the XDG directories at the writable tmpfs instead.
BROWSER_HOME="${BROWSER_HOME:-/tmp/browser-home}"
HOME="${BROWSER_HOME}"
XDG_CACHE_HOME="${BROWSER_HOME}/.cache"
XDG_CONFIG_HOME="${BROWSER_HOME}/.config"
XDG_RUNTIME_DIR="${BROWSER_HOME}/run"
mkdir -p "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
chmod 700 "${XDG_RUNTIME_DIR}"
export HOME XDG_CACHE_HOME XDG_CONFIG_HOME XDG_RUNTIME_DIR

if is_enabled "${BROWSER_INTERACTIVE_HITL_ENABLED:-false}"; then
    # ONE display stack per session slot. A single shared display was the reason
    # interactive HITL was capped at one session: x11vnc exports a WHOLE display,
    # so two headful browsers on one desktop would let a grant issued for session A
    # stream session B's window. Slot i therefore gets its own Xvfb, its own window
    # manager and its own x11vnc:
    #
    #   display :(BROWSER_DISPLAY_NUM + i)  <-  x11vnc on (BROWSER_VNC_PORT + i)
    #
    # browser_service.display_pool leases slot i to exactly one session and the
    # relay connects only to that slot's port, so isolation holds by construction.
    DISPLAY_SLOTS="${BROWSER_DISPLAY_SLOTS:-${PLAYWRIGHT_MAX_SESSIONS:-1}}"
    case "${DISPLAY_SLOTS}" in
        '' | *[!0-9]*)
            echo "browser-service: BROWSER_DISPLAY_SLOTS must be a positive integer" >&2
            exit 1
            ;;
    esac
    if [ "${DISPLAY_SLOTS}" -lt 1 ] || [ "${DISPLAY_SLOTS}" -gt 10 ]; then
        echo "browser-service: BROWSER_DISPLAY_SLOTS must be between 1 and 10" >&2
        exit 1
    fi

    echo "browser-service: interactive HITL enabled, starting ${DISPLAY_SLOTS} display stack(s)" >&2

    slot=0
    while [ "${slot}" -lt "${DISPLAY_SLOTS}" ]; do
        slot_display=$((DISPLAY_NUM + slot))
        slot_vnc_port=$((VNC_PORT + slot))
        slot_view_vnc_port=$((VIEW_VNC_PORT + slot))

        # Virtual framebuffer: Chromium can then run headful, which is what makes a
        # human handoff (CAPTCHA, account chooser, MFA) actually solvable.
        Xvfb ":${slot_display}" -screen 0 "${SCREEN_GEOMETRY}" -nolisten tcp &

        # Wait for THIS slot's X socket rather than sleeping blindly.
        i=0
        while [ ! -e "/tmp/.X11-unix/X${slot_display}" ]; do
            i=$((i + 1))
            if [ "$i" -gt 100 ]; then
                echo "browser-service: Xvfb failed to start on :${slot_display}" >&2
                exit 1
            fi
            sleep 0.1
        done

        # A minimal window manager so dialogs and popups are placed sanely. Bound
        # to this slot's display, so each desktop is managed independently.
        DISPLAY=":${slot_display}" fluxbox >/dev/null 2>&1 &

        # -localhost is the load-bearing flag: x11vnc accepts connections only from
        # inside this container, so there is no raw public VNC port. -nopw is safe
        # ONLY because of that binding plus the authenticated relay in front of it;
        # a VNC password here would be a second secret with no added protection.
        x11vnc \
            -display ":${slot_display}" \
            -rfbport "${slot_vnc_port}" \
            -localhost \
            -nopw \
            -shared \
            -forever \
            -noxdamage \
            -quiet \
            >/dev/null 2>&1 &

        # A second loopback-only server exports the SAME private display but
        # refuses keyboard, pointer and clipboard input at the VNC server. This is
        # the autonomous ``browser_running`` stream. Even a modified noVNC client
        # cannot upgrade a signed view grant into browser control.
        x11vnc \
            -display ":${slot_display}" \
            -rfbport "${slot_view_vnc_port}" \
            -localhost \
            -nopw \
            -shared \
            -forever \
            -viewonly \
            -noxdamage \
            -quiet \
            >/dev/null 2>&1 &

        slot=$((slot + 1))
    done

    # The process-level DISPLAY is the FIRST slot only as a sane default for any
    # incidental X client. Each browser session is launched with its own leased
    # DISPLAY (see PlaywrightBrowserWorker._launch_env), so no session relies on
    # inheriting this value.
    export DISPLAY=":${DISPLAY_NUM}"
else
    echo "browser-service: interactive HITL disabled, headless only" >&2
fi

exec "$@"
