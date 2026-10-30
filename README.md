# Network Port Scanner

A multithreaded TCP port scanner written in **Python** (standard library only). It finds open ports on a host, identifies the common service for each one, and flags ports that are risky when exposed (Telnet, FTP, SMB, RDP and others) with a short remediation hint.

> **Legal notice:** only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal.

## Features
- Port lists and ranges (`22,80,443` or `1-1024`)
- Thread pool for fast scanning, with adjustable timeout and workers
- Service name lookup and security warnings for risky ports
- JSON report export
- Unit tests that run against a local test socket

## Requirements
Python 3.8+

## Usage
```bash
python port_scanner.py 127.0.0.1
python port_scanner.py 192.168.1.1 -p 20-25,80,443,3389
python port_scanner.py localhost -p 1-65535 -w 200 -o report.json
```

## Run the tests
```bash
python -m unittest -v
```

## Skills demonstrated
TCP/IP and sockets, network security fundamentals (attack surface and exposed services), concurrency, input validation, secure-by-default reporting, unit testing.

## License
MIT
