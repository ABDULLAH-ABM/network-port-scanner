#!/usr/bin/env python3
"""Multithreaded TCP port scanner with a basic security risk report.

Only scan systems you own or have explicit written permission to test.
"""
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

RISKY_PORTS = {
    21: "FTP sends credentials in clear text. Prefer SFTP.",
    23: "Telnet is unencrypted. Use SSH instead.",
    135: "Windows RPC. Should not be exposed to untrusted networks.",
    139: "NetBIOS. Disable if not needed.",
    445: "SMB is a frequent attack target. Restrict access and patch.",
    3306: "MySQL exposed. Restrict to trusted hosts only.",
    3389: "RDP exposed. Protect with VPN and MFA.",
    5900: "VNC exposed. Use a tunnel/VPN and strong authentication.",
}


def parse_ports(spec):
    """Parse '22,80,8000-8100' into a sorted list of valid port numbers."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
        else:
            start = end = int(part)
        if not (1 <= start <= end <= 65535):
            raise ValueError(f"Invalid port range: {part}")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("No ports given.")
    return sorted(ports)


def is_open(host, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan(host, ports, timeout=0.5, workers=100):
    """Return the sorted list of open ports on host."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: (p, is_open(host, p, timeout)), ports)
    return sorted(p for p, opened in results if opened)


def build_report(host, ip, open_ports, scanned):
    return {
        "target": host,
        "ip": ip,
        "scanned_ports": scanned,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": [
            {"port": p, "service": service_name(p), "warning": RISKY_PORTS.get(p)}
            for p in open_ports
        ],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Simple TCP port scanner")
    ap.add_argument("target", help="hostname or IP address (must be authorised)")
    ap.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80,443 or 1-1024")
    ap.add_argument("-t", "--timeout", type=float, default=0.5)
    ap.add_argument("-w", "--workers", type=int, default=100)
    ap.add_argument("-o", "--output", help="save the report as JSON")
    args = ap.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        ip = socket.gethostbyname(args.target)
    except (ValueError, socket.gaierror) as exc:
        sys.exit(f"Error: {exc}")

    print(f"Scanning {args.target} ({ip}), {len(ports)} ports. Only scan systems you are authorised to test.")
    report = build_report(args.target, ip, scan(ip, ports, args.timeout, args.workers), len(ports))

    if not report["open_ports"]:
        print("No open ports found.")
    for entry in report["open_ports"]:
        print(f"  {entry['port']:<6} open  {entry['service']}")
        if entry["warning"]:
            print(f"         WARNING: {entry['warning']}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
