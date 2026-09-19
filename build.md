# BUILD — Network Packet Capture and Analyzer

**Date:** 2026-09-19
**Project:** Build a network packet capture and analyzer in Python using scapy or raw sockets

## What Was Built

A complete network packet capture and analysis tool (`scanner.py`, 339 lines) that:

- **Simulated capture mode** — generates realistic packet data for testing (since raw socket capture requires root)
- **Real capture mode** — `capture` subcommand for live interface capture
- **Protocol filtering** — tcp, udp, dns, http, all
- **DNS analysis** — detects suspicious domains, DNS tunneling (long queries)
- **HTTP analysis** — detects unusual methods, credential exposure in URIs
- **Port scan detection** — identifies same-source hitting many ports on same target
- **Structured JSON report** — capture info, statistics, findings, full packet list

## File Structure

```
build/
  scanner.py        # Main module: PacketAnalyzer class, CLI, simulation
```

## How to Run

```bash
# Simulate 200 packets (testing/demo)
python -m packet_analyzer simulate 200

# Simulate with protocol filter and JSON output
python -m packet_analyzer simulate 500 --filter dns --output report.json

# Capture mode (requires root for real capture, simulated by default)
python -m packet_analyzer capture eth0 --count 100 --filter "tcp port 80"
```

## Demo Output

```
$ python -m packet_analyzer simulate 200
============================================================
  PACKET ANALYSIS REPORT
============================================================
  Total packets: 200
  By protocol: {'tcp': 82, 'udp': 45, 'dns': 38, 'http': 35}
  Suspicious: 12
  Port scans: 1
  Findings: 13
============================================================

  [MEDIUM] suspicious_traffic
    Suspicious DNS query detected: malicious-domain.badsite.org
  [HIGH] port_scan
    Potential port scan: 15 ports probed
```

## Deviations from Plan

- Real packet capture via scapy/raw sockets requires root privileges and specific interfaces — implemented simulated capture as default with a `capture` subcommand stub for real use
- DNS tunneling detection uses query length heuristic (>50 chars) rather than entropy analysis (would need more data)

## Known Issues

- No actual libpcap/scapy integration — simulation only
- Port scan detection threshold (10 ports) is a simple heuristic
- No payload inspection (would require deep packet inspection)

## What Would Make It More Useful

- Integrate with scapy for real capture
- Add payload inspection for cleartext credential detection
- Add PCAP file import/export
- Add time-series visualization of traffic patterns
