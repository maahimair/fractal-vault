""" import socketio

sio = socketio.Client()

@sio.event
def connect():
    print("Connected to Fractal Vault live stream")

@sio.on("trust_event")
def on_trust_event(data):
    print("LIVE TRUST EVENT:")
    print(data)
    print("-" * 40)

sio.connect("http://127.0.0.1:3000")
sio.wait() """
# simulator/live_monitor.py
# Fractal Vault — Live Trust Event Monitor
# Secured and debugged version

import os
import sys
import json
from datetime import datetime

import socketio
from dotenv import load_dotenv

# ─── Config ──────────────────────────────────────────────────────────────────

load_dotenv()

GATEWAY_URL         = os.environ.get("GATEWAY_URL", "http://127.0.0.1:3000")
RECONNECT_ATTEMPTS  = 10
RECONNECT_DELAY     = 2    # seconds between reconnect attempts
RECONNECT_DELAY_MAX = 30   # cap backoff at 30 seconds

# ─── Status colour helpers (ANSI, Windows-safe via colorama if available) ────

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    def green(s):  return Fore.GREEN  + s + Style.RESET_ALL
    def yellow(s): return Fore.YELLOW + s + Style.RESET_ALL
    def red(s):    return Fore.RED    + s + Style.RESET_ALL
    def cyan(s):   return Fore.CYAN   + s + Style.RESET_ALL
    def dim(s):    return Style.DIM   + s + Style.RESET_ALL
except ImportError:
    # colorama not installed — plain text fallback
    def green(s):  return s
    def yellow(s): return s
    def red(s):    return s
    def cyan(s):   return s
    def dim(s):    return s

# ─── Counters ─────────────────────────────────────────────────────────────────

stats = {"total": 0, "allowed": 0, "stepup": 0, "denied": 0, "anomalies": 0}

# ─── Socket.IO Client ────────────────────────────────────────────────────────

sio = socketio.Client(
    reconnection=True,
    reconnection_attempts=RECONNECT_ATTEMPTS,
    reconnection_delay=RECONNECT_DELAY,
    reconnection_delay_max=RECONNECT_DELAY_MAX,
    logger=False,
    engineio_logger=False
)

# ─── Event Handlers ──────────────────────────────────────────────────────────

@sio.event
def connect():
    ts = datetime.now().strftime("%H:%M:%S")
    print(cyan(f"\n[{ts}] ✔ Connected to Fractal Vault Gateway — {GATEWAY_URL}"))
    print(dim("─" * 60))
    print(dim(f"{'TIME':<10} {'SCORE':>5}  {'STATUS':<20} {'ANOMALY':<8} {'LOGINS':>6}"))
    print(dim("─" * 60))


@sio.event
def disconnect():
    ts = datetime.now().strftime("%H:%M:%S")
    print(yellow(f"\n[{ts}] ⚠ Disconnected from gateway. Attempting reconnect..."))


@sio.event
def connect_error(data):
    ts = datetime.now().strftime("%H:%M:%S")
    print(red(f"[{ts}] ✖ Connection error: {data}"))
    print(red(f"[{ts}] Make sure the Node.js gateway is running at {GATEWAY_URL}"))


@sio.on("trust_event")
def on_trust_event(data):
    """
    Handles every trust evaluation broadcast by the gateway.
    Prints a formatted one-liner + raw JSON for demo/interview visibility.
    """
    ts      = data.get("timestamp", datetime.now().strftime("%H:%M:%S"))
    score   = data.get("trust_score", "?")
    status  = str(data.get("status", "UNKNOWN")).upper()
    anomaly = data.get("is_anomaly", False)
    logins  = data.get("factors_checked")   # not in payload; kept for future

    # Update counters
    stats["total"] += 1
    if status == "ALLOWED":
        stats["allowed"]  += 1
    elif status == "DENIED":
        stats["denied"]   += 1
    else:
        stats["stepup"]   += 1
    if anomaly:
        stats["anomalies"] += 1

    # Colour-code by status
    if status == "ALLOWED":
        status_str = green(f"{status:<20}")
        score_str  = green(f"{score:>5}")
    elif status == "DENIED":
        status_str = red(f"{status:<20}")
        score_str  = red(f"{score:>5}")
    else:
        status_str = yellow(f"{status:<20}")
        score_str  = yellow(f"{score:>5}")

    anomaly_str = red("YES     ") if anomaly else dim("NO      ")

    print(f"[{ts}] {score_str}  {status_str} {anomaly_str}")

    # Full JSON for demo/interview mode
    print(dim("  Raw: " + json.dumps(data, separators=(",", ":"))))
    print(dim("─" * 60))

    # Running totals every 10 events
    if stats["total"] % 10 == 0:
        _print_summary()


def _print_summary():
    t = stats["total"] or 1
    print(cyan(
        f"\n[SUMMARY] {stats['total']} events | "
        f"Allowed: {stats['allowed']} ({stats['allowed']/t*100:.0f}%) | "
        f"Step-Up: {stats['stepup']} ({stats['stepup']/t*100:.0f}%) | "
        f"Denied: {stats['denied']} ({stats['denied']/t*100:.0f}%) | "
        f"Anomalies: {stats['anomalies']}"
    ))
    print(dim("─" * 60))

# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(cyan(f"[MONITOR] Fractal Vault Live Monitor"))
    print(cyan(f"[MONITOR] Connecting to {GATEWAY_URL} ..."))

    try:
        sio.connect(
            GATEWAY_URL,
            transports=["websocket"],
            wait_timeout=10
        )
        sio.wait()
    except socketio.exceptions.ConnectionError:
        print(red(f"[FATAL] Could not connect to {GATEWAY_URL}"))
        print(red("[FATAL] Is the Node.js gateway running? (cd gateway-node && npm start)"))
        sys.exit(1)
    except KeyboardInterrupt:
        print(cyan("\n[MONITOR] Shutting down..."))
        _print_summary()
        sio.disconnect()
        sys.exit(0)