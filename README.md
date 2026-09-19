# Packet Capture

```text
########     ######     ######## ##      ## ########## ##########
##      ## ##      ## ##         ##    ##   ##             ##    
########   ##      ## ##         ######     ########       ##    
##         ########## ##         ##    ##   ##             ##    
##         ##      ##   ######## ##      ## ##########     ##    
```

Network packet capture and analyzer in Python using raw sockets. Capture, filter, and analyze network traffic from the command line.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **Packet Capture** — Capture network packets using raw sockets
- **Protocol Filtering** — Filter by protocol (TCP, UDP, ICMP, etc.)
- **Packet Analysis** — Decode and display packet headers and payloads
- **Statistical Summary** — Generate traffic statistics and summaries
- **CLI Interface** — Command-line driven with filtering options

## Installation

```bash
git clone https://github.com/aimansam/packet-capture
cd packet-capture
pip install -e .
```

## Quick Start

Run the safe simulation mode (the current implementation does not capture live packets):

```bash
packet-analyzer simulate 100
```

Capture and filter by protocol:

```bash
packet-analyzer capture eth0 --count 100
```

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)
- Capture mode currently simulates traffic; live capture and PCAP import are planned.

## Limitations

Packet capture requires root privileges or the `CAP_NET_RAW` capability.
Some protocol decoding is basic — for full protocol analysis, consider
using `scapy` or `dpkt` as additional dependencies.

## License

MIT
