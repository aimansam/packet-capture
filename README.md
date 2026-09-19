# Packet Capture

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

Capture packets on a network interface:

```bash
python -m scanner capture --interface eth0 --count 100
```

Capture and filter by protocol:

```bash
python -m scanner capture --interface eth0 --protocol TCP
```

Analyze a PCAP file:

```bash
python -m scanner analyze capture.pcap
```

Generate traffic statistics:

```bash
python -m scanner stats --interface eth0 --duration 60
```

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)
- Linux with raw socket support (requires root or CAP_NET_RAW)

## Limitations

Packet capture requires root privileges or the `CAP_NET_RAW` capability.
Some protocol decoding is basic — for full protocol analysis, consider
using `scapy` or `dpkt` as additional dependencies.

## License

MIT

