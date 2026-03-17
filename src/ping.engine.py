"""
ping_engine.py
--------------
NetMonitor Ping Engine v1.5
Uses icmplib 3.0.4 ICMPv4Socket for raw per-packet ICMP echo requests.
Prints each ping result to the screen in real time.

Requirements:
    pip install icmplib==3.0.4

Privileges:
    sudo setcap cap_net_raw+ep $(readlink -f $(which python3))
    python3 ping_engine.py
"""

import asyncio
import os
import time
from datetime import datetime, timezone

from icmplib import ICMPv4Socket, ICMPRequest, ICMPReply, resolve
from icmplib.exceptions import (
    ICMPLibError,
    NameLookupError,
    TimeoutExceeded,
    DestinationUnreachable,
    TimeExceeded,
)


# ---------------------------------------------------------------------------
# Configuration (will later be read from config.json)
# ---------------------------------------------------------------------------

TARGETS = [
    {"host": "8.8.8.8",   "label": "Google DNS"},
    {"host": "1.1.1.1",   "label": "Cloudflare DNS"},
    {"host": "10.255.255.1",   "label": "Google DNS 2"},
]

PING_INTERVAL = 0.5      # seconds between each full ping cycle
PING_TIMEOUT  = 2      # seconds to wait for a reply per packet
PING_PAYLOAD  = 56     # bytes of ICMP payload (standard default)


# ---------------------------------------------------------------------------
# Data record builder
# ---------------------------------------------------------------------------

def build_record(
    host: str,
    label: str,
    ip_address: str,
    icmp_seq: int,
    timestamp: str,
    rtt_ms: float | None,
    bytes_received: int | None,
    packet_loss: int,
    error_type: str,
) -> dict:
    """
    Assembles a single ping echo record.
    This dict maps 1:1 to an InfluxDB 3 measurement row.

    Notes:
    - ttl is not exposed by icmplib's ICMPReply at the socket level
    - rtt_ms is None when the packet is lost
    - packet_loss: 0 = received, 1 = lost
    - error_type:  "" | "timeout" | "unreachable" | "time_exceeded" |
                   "dns_failure" | "error:<ExceptionName>"
    """
    return {
        "timestamp":      timestamp,
        "host":           host,
        "label":          label,
        "ip_address":     ip_address,
        "icmp_seq":       icmp_seq,
        "rtt_ms":         rtt_ms,
        "bytes_received": bytes_received,
        "packet_loss":    packet_loss,
        "error_type":     error_type,
    }


# ---------------------------------------------------------------------------
# Single ping using ICMPv4Socket
# ---------------------------------------------------------------------------

def ping_once(host: str, label: str, icmp_seq: int) -> dict:
    """
    Sends a single ICMP echo request to host.
    Returns a populated record dict.

    Uses icmplib's resolve() for DNS — consistent with the library.
    ICMPv4Socket is blocking; called via run_in_executor to stay async.

    ICMPRequest parameters (icmplib 3.0.4):
        destination  : str   — target IP address
        id           : int   — ICMP identifier (matched on reply)
        sequence     : int   — ICMP sequence number
        payload_size : int   — bytes of payload (default 56)
        ttl          : int   — outgoing TTL (default 64)
        traffic_class: int   — DSCP/ECN (default 0)
        payload      : bytes — custom payload (default random)
    Note: timeout is NOT a parameter of ICMPRequest.

    ICMPv4Socket.receive(request, timeout) parameters:
        request : ICMPRequest — used to match the reply
        timeout : float       — seconds to wait (default 2)

    ICMPReply properties available (icmplib 3.0.4):
        source         : str   — IP address that replied
        family         : int   — 4 or 6
        id             : int   — ICMP identifier
        sequence       : int   — ICMP sequence number
        type           : int   — ICMP type code
        code           : int   — ICMP code
        bytes_received : int   — number of bytes received
        time           : float — round-trip time in SECONDS
    Note: time_to_live (TTL) is NOT exposed on ICMPReply.
    """

    # Resolve hostname to IP using icmplib's own resolver
    try:
        ip_address = resolve(host)[0]
    except NameLookupError:
        return build_record(
            host=host,
            label=label,
            ip_address="unresolved",
            icmp_seq=icmp_seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            rtt_ms=None,
            bytes_received=None,
            packet_loss=1,
            error_type="dns_failure",
        )

    timestamp = datetime.now(timezone.utc).isoformat()

    # Build the ICMP echo request — no timeout here
    request = ICMPRequest(
        destination=ip_address,
        id=os.getpid() & 0xFFFF,
        sequence=icmp_seq,
        payload_size=PING_PAYLOAD,
    )

    try:
        with ICMPv4Socket() as sock:
            sock.send(request)

            # timeout is passed to receive(), not to ICMPRequest
            reply: ICMPReply = sock.receive(request, PING_TIMEOUT)

            # raises DestinationUnreachable, TimeExceeded, or ICMPError
            # if the reply is not a clean Echo Reply
            reply.raise_for_status()

            # reply.time is in seconds — convert to milliseconds
            rtt_ms = round((reply.time - request.time) * 1000, 3)

            # bytes_received is the correct property name in icmplib 3.x
            # (received_bytes was the old deprecated name)
            return build_record(
                host=host,
                label=label,
                ip_address=ip_address,
                icmp_seq=icmp_seq,
                timestamp=timestamp,
                rtt_ms=rtt_ms,
                bytes_received=reply.bytes_received,
                packet_loss=0,
                error_type="",
            )

    except TimeoutExceeded:
        return build_record(
            host=host,
            label=label,
            ip_address=ip_address,
            icmp_seq=icmp_seq,
            timestamp=timestamp,
            rtt_ms=None,
            bytes_received=None,
            packet_loss=1,
            error_type="timeout",
        )

    except DestinationUnreachable:
        return build_record(
            host=host,
            label=label,
            ip_address=ip_address,
            icmp_seq=icmp_seq,
            timestamp=timestamp,
            rtt_ms=None,
            bytes_received=None,
            packet_loss=1,
            error_type="unreachable",
        )

    except TimeExceeded:
        # TTL expired in transit — packet never reached the destination
        return build_record(
            host=host,
            label=label,
            ip_address=ip_address,
            icmp_seq=icmp_seq,
            timestamp=timestamp,
            rtt_ms=None,
            bytes_received=None,
            packet_loss=1,
            error_type="time_exceeded",
        )

    except ICMPLibError as e:
        # Catches any remaining icmplib error (socket errors, etc.)
        return build_record(
            host=host,
            label=label,
            ip_address=ip_address,
            icmp_seq=icmp_seq,
            timestamp=timestamp,
            rtt_ms=None,
            bytes_received=None,
            packet_loss=1,
            error_type=f"error:{type(e).__name__}",
        )


# ---------------------------------------------------------------------------
# Output printer
# ---------------------------------------------------------------------------

def print_record(record: dict) -> None:
    """
    Formats and prints a single ping record to stdout.
    Colour-codes the result: green for success, yellow for timeout,
    red for all other failure types.
    """

    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"

    ts    = record["timestamp"]
    label = record["label"]
    ip    = record["ip_address"]
    seq   = record["icmp_seq"]
    loss  = record["packet_loss"]
    err   = record["error_type"]

    if loss == 0:
        rtt  = record["rtt_ms"]
        byt  = record["bytes_received"]
        color  = GREEN
        status = f"rtt={rtt:.3f}ms  bytes={byt}"
    else:
        color  = YELLOW if err == "timeout" else RED
        status = f"LOST  reason={err}"

    print(
        f"{color}"
        f"[{ts}]  "
        f"{label:<18}  "
        f"{ip:<16}  "
        f"seq={seq:<6}  "
        f"{status}"
        f"{RESET}"
    )


# ---------------------------------------------------------------------------
# Async ping cycle
# ---------------------------------------------------------------------------

async def ping_target(
    host: str,
    label: str,
    icmp_seq: int,
    loop: asyncio.AbstractEventLoop,
) -> dict:
    """
    Runs the blocking ping_once() in a thread executor so it does not
    block the event loop while other targets are being pinged concurrently.
    """
    record = await loop.run_in_executor(
        None, ping_once, host, label, icmp_seq
    )
    return record


async def ping_cycle(
    seq_counters: dict,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """
    Fires one ping to every target concurrently.
    Collects and prints all results for this cycle.
    """
    tasks = [
        ping_target(
            t["host"],
            t["label"],
            seq_counters[t["host"]],
            loop,
        )
        for t in TARGETS
    ]

    # Advance all sequence counters before awaiting results
    for t in TARGETS:
        seq_counters[t["host"]] = (seq_counters[t["host"]] + 1) & 0xFFFF

    results = await asyncio.gather(*tasks)

    print()
    for record in results:
        print_record(record)
        # --- future integration hooks (do not remove) ---
        # await influx_writer.write(record)
        # await alert_engine.evaluate(record)
        # await websocket_manager.broadcast(record)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run() -> None:
    """
    Main engine loop. Runs ping cycles indefinitely at the configured
    interval. Accounts for cycle execution time so the interval is
    wall-clock accurate rather than drifting on slow networks.
    """
    loop = asyncio.get_event_loop()

    # Initialise per-target sequence counters starting at 0
    seq_counters = {t["host"]: 0 for t in TARGETS}

    print("=" * 70)
    print(" Ninja Netmon Ping Engine v0.5")
    print(f" Targets  : {', '.join(t['host'] for t in TARGETS)}")
    print(f" Interval : {PING_INTERVAL}s")
    print(f" Timeout  : {PING_TIMEOUT}s per packet")
    print(f" icmplib  : 3.0.4")
    print("=" * 70)

    cycle = 0
    while True:
        cycle += 1
        cycle_start = time.monotonic()

        print(f"\n--- Cycle {cycle} ---")
        await ping_cycle(seq_counters, loop)

        elapsed   = time.monotonic() - cycle_start
        sleep_for = max(0.0, PING_INTERVAL - elapsed)
        await asyncio.sleep(sleep_for)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n\nPing engine stopped.")
    except PermissionError:
        print(
            "\n[ERROR] Permission denied — raw ICMP sockets require "
            "elevated privileges.\n"
            "Grant the capability with:\n"
            "  sudo setcap cap_net_raw+ep $(readlink -f $(which python3))\n"
            "Then run again without sudo.\n"
        )