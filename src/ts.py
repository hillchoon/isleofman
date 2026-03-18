import os
import time
from datetime import datetime
from icmplib import ICMPv4Socket, ICMPRequest, ICMPReply

ip      = input("Destination IP: ")
payload = 0

request = ICMPRequest(
    destination=ip,
    id=os.getpid() & 0xFFFF,
    sequence=1,
    payload_size=payload,
)

print(f"Sending to {ip} ...")

with ICMPv4Socket() as sock:
    t_send = time.perf_counter()
    sock.send(request)
    
    try:
        reply: ICMPReply = sock.receive(request, 2)
        t_recv = time.perf_counter()
        print(f"Request timestamp: {request.time} / {datetime.fromtimestamp(request.time).strftime('%Y-%m-%d %H:%M:%S.%f')}")
        print(f"Reply timestamp: {reply.time} / {datetime.fromtimestamp(reply.time).strftime('%Y-%m-%d %H:%M:%S.%f')}")
        print(f"RTT : {round((reply.time - request.time) * 1000, 3)}")
        reply.raise_for_status()
        
        rtt_ms = round((t_recv - t_send) * 1000, 3)
        print(f"Reply from {reply.source} (RTT per perf_count)={rtt_ms}ms  bytes={reply.bytes_received}")

    except Exception as e:
        print(f"Result: {type(e).__name__} — {e}")
