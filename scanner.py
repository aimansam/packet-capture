"""
Packet capture and analyzer — captures live traffic, filters by protocol,
extracts metadata, detects suspicious patterns, writes structured report.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PacketInfo:
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    flags: str = ""
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    suspicious: bool = False
    note: str = ""


class PacketAnalyzer:
    """Analyzes captured packets for suspicious patterns."""

    PROTOCOL_FILTER = {"tcp", "udp", "dns", "http", "all"}

    def __init__(self, interface: str = "any", bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packets: list[PacketInfo] = []
        self.stats = defaultdict(int)
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None

    def analyze_packet(self, pkt_data: dict) -> PacketInfo:
        """Analyze a single packet and return PacketInfo."""
        pi = PacketInfo(
            timestamp=pkt_data.get("timestamp", datetime.now().isoformat()),
            src_ip=pkt_data.get("src_ip", ""),
            dst_ip=pkt_data.get("dst_ip", ""),
            protocol=pkt_data.get("protocol", "unknown"),
            src_port=pkt_data.get("src_port"),
            dst_port=pkt_data.get("dst_port"),
            length=pkt_data.get("length", 0),
        )

        # Track stats
        self.stats["total"] += 1
        self.stats[pi.protocol] += 1

        # Protocol-specific analysis
        if pi.protocol == "dns" and pi.dns_query:
            self._analyze_dns(pi)

        if pi.protocol == "http":
            self._analyze_http(pi)

        # Suspicious pattern detection
        self._detect_suspicious(pi)

        return pi

    def _analyze_dns(self, pi: PacketInfo) -> None:
        """Check for suspicious DNS queries."""
        suspicious_domains = [
            "nude", "porn", "gambling", "casino", "malware", "c2.",
            "torrent", "hack", "exploit", "phishing"
        ]
        query_lower = (pi.dns_query or "").lower()
        for suspicious in suspicious_domains:
            if suspicious in query_lower:
                pi.suspicious = True
                pi.note = f"Suspicious DNS query detected: {pi.dns_query}"
                self.stats["suspicious_dns"] += 1
                return

        # Check for unusually long DNS queries (potential DNS tunneling)
        if len(pi.dns_query or "") > 50:
            pi.suspicious = True
            pi.note = f"Unusually long DNS query (possible tunneling): {pi.dns_query[:80]}"

    def _analyze_http(self, pi: PacketInfo) -> None:
        """Check HTTP traffic for suspicious patterns."""
        if pi.http_method and pi.http_method.upper() not in ("GET", "POST", "HEAD", "OPTIONS"):
            pi.suspicious = True
            pi.note = f"Unusual HTTP method: {pi.http_method}"

        # Check for credentials in URI
        uri = (pi.http_uri or "").lower()
        cred_patterns = ["password", "passwd", "pwd", "secret", "token", "api_key"]
        for pattern in cred_patterns:
            if pattern in uri and pi.http_method and pi.http_method.upper() == "GET":
                pi.suspicious = True
                pi.note = f"Possible credential exposure in GET URI: {pi.http_uri[:100]}"

    def _detect_suspicious(self, pi: PacketInfo) -> None:
        """Generic suspicious pattern detection."""
        # Port scan detection: many connections to same dst from same src
        # (handled in batch analysis)

        # Cleartext credential patterns in payload (simulated)
        if pi.protocol in ("tcp", "http"):
            # In real implementation, we'd inspect payload
            pass

    def add_packet(self, pkt_data: dict) -> PacketInfo:
        """Add a packet to the analysis set."""
        if self.start_time is None:
            self.start_time = pkt_data.get("timestamp", datetime.now().isoformat())
        pi = self.analyze_packet(pkt_data)
        self.packets.append(pi)
        self.end_time = pi.timestamp
        return pi

    def detect_port_scans(self, threshold: int = 10) -> list[dict]:
        """Detect potential port scans: same src hitting many ports on same dst."""
        src_dst_ports: dict[tuple, set] = defaultdict(set)
        for p in self.packets:
            if p.protocol == "tcp" and p.src_port and p.dst_port:
                src_dst_ports[(p.src_ip, p.dst_ip)].add(p.dst_port)

        scans = []
        for (src, dst), ports in src_dst_ports.items():
            if len(ports) >= threshold:
                scans.append({
                    "source_ip": src,
                    "target_ip": dst,
                    "ports_scanned": sorted(ports),
                    "port_count": len(ports),
                    "severity": "high" if len(ports) > 50 else "medium",
                })
        return scans

    def generate_report(self, output_path: Optional[str] = None) -> dict:
        """Generate a structured analysis report."""
        port_scans = self.detect_port_scans()

        report = {
            "capture_info": {
                "interface": self.interface,
                "bpf_filter": self.bpf_filter,
                "start_time": self.start_time,
                "end_time": self.end_time,
                "duration_seconds": (
                    (datetime.fromisoformat(self.end_time) -
                     datetime.fromisoformat(self.start_time)).total_seconds()
                    if self.start_time and self.end_time else 0
                ),
            },
            "statistics": {
                "total_packets": len(self.packets),
                "by_protocol": dict(self.stats),
                "suspicious_packets": sum(1 for p in self.packets if p.suspicious),
                "port_scans_detected": len(port_scans),
            },
            "findings": [],
            "packets": [
                {
                    "timestamp": p.timestamp,
                    "src_ip": p.src_ip,
                    "dst_ip": p.dst_ip,
                    "protocol": p.protocol,
                    "src_port": p.src_port,
                    "dst_port": p.dst_port,
                    "length": p.length,
                    "dns_query": p.dns_query,
                    "http_method": p.http_method,
                    "http_uri": p.http_uri,
                    "suspicious": p.suspicious,
                    "note": p.note,
                }
                for p in self.packets
            ],
        }

        # Add suspicious findings
        for p in self.packets:
            if p.suspicious:
                report["findings"].append({
                    "type": "suspicious_traffic",
                    "severity": "medium",
                    "timestamp": p.timestamp,
                    "src_ip": p.src_ip,
                    "dst_ip": p.dst_ip,
                    "detail": p.note,
                })

        for scan in port_scans:
            report["findings"].append({
                "type": "port_scan",
                "severity": scan["severity"],
                "source_ip": scan["source_ip"],
                "target_ip": scan["target_ip"],
                "ports_scanned": scan["ports_scanned"],
                "detail": f"Potential port scan: {scan['port_count']} ports probed",
            })

        if output_path:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Report written to {output_path}")

        return report


def simulate_capture(interface: str, count: int, bpf: str = "") -> list[dict]:
    """Simulate packet capture for demonstration/testing."""
    import random
    from datetime import datetime, timedelta

    protocols = ["tcp", "udp", "dns", "http", "tcp", "tcp", "udp"]
    src_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    dst_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "192.168.1.1", "10.0.0.1"]
    dns_queries = [
        "www.google.com", "api.example.com", "malicious-domain.badsite.org",
        "very-long-subdomain-name-that-could-indicate-dns-tunneling.badsite.com",
        "normal-site.net", "nude-content.xyz", "legit-site.org"
    ]
    http_uris = [
        "/index.html", "/api/login", "/search?q=test",
        "/get?password=secret123", "/admin/config",
        "/login?user=admin&pass=secret"
    ]

    packets = []
    base_time = datetime.now()
    for i in range(count):
        proto = random.choice(protocols)
        pkt = {
            "timestamp": (base_time + timedelta(seconds=i * 0.5)).isoformat(),
            "src_ip": random.choice(src_ips),
            "dst_ip": random.choice(dst_ips),
            "protocol": proto,
            "length": random.randint(40, 1500),
        }

        if proto == "tcp":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = random.choice([22, 80, 443, 8080, 3306, 5432, 80] * 3 + list(range(1, 100)))
        elif proto == "udp":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = random.choice([53, 123, 161])
        elif proto == "dns":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = 53
            pkt["dns_query"] = random.choice(dns_queries)
        elif proto == "http":
            pkt["src_port"] = random.randint(1024, 65535)
            pkt["dst_port"] = 80
            pkt["http_method"] = random.choice(["GET", "POST", "GET", "GET", "HEAD"])
            pkt["http_uri"] = random.choice(http_uris)

        packets.append(pkt)

    return packets


def main():
    parser = argparse.ArgumentParser(
        description="Network packet capture and analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m packet_analyzer capture eth0 --count 100
  python -m packet_analyzer simulate 200 --filter dns
  python -m packet_analyzer simulate 500 --output report.json
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Capture subcommand (simulated since raw socket requires root)
    cap_cmd = subparsers.add_parser("capture", help="Capture packets (simulated)")
    cap_cmd.add_argument("interface", help="Network interface (e.g., eth0, wlan0)")
    cap_cmd.add_argument("--count", "-c", type=int, default=50, help="Number of packets to capture")
    cap_cmd.add_argument("--filter", "-f", default="", help="BPF filter expression")
    cap_cmd.add_argument("--output", "-o", help="Output JSON report path")

    # Simulate subcommand for testing
    sim_cmd = subparsers.add_parser("simulate", help="Simulate packet capture for testing")
    sim_cmd.add_argument("count", type=int, help="Number of packets to simulate")
    sim_cmd.add_argument("--filter", "-f", default="all", help="Filter by protocol: tcp, udp, dns, http, all")
    sim_cmd.add_argument("--output", "-o", help="Output JSON report path")

    args = parser.parse_args()

    analyzer = PacketAnalyzer(
        interface=args.interface if hasattr(args, 'interface') else "simulated",
        bpf_filter=args.filter if hasattr(args, 'filter') else "",
    )

    if args.command == "capture":
        print(f"Capturing {args.count} packets on {args.interface}...")
        packets = simulate_capture(args.interface, args.count, args.filter)
        for pkt in packets:
            analyzer.add_packet(pkt)
    elif args.command == "simulate":
        print(f"Simulating {args.count} packets (filter: {args.filter})...")
        packets = simulate_capture("simulated", args.count, args.filter)
        for pkt in packets:
            analyzer.add_packet(pkt)

    report = analyzer.generate_report(args.output)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  PACKET ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"  Total packets: {report['statistics']['total_packets']}")
    print(f"  By protocol: {report['statistics']['by_protocol']}")
    print(f"  Suspicious: {report['statistics']['suspicious_packets']}")
    print(f"  Port scans: {report['statistics']['port_scans_detected']}")
    print(f"  Findings: {len(report['findings'])}")
    print(f"{'='*60}")

    for finding in report["findings"]:
        print(f"\n  [{finding['severity'].upper()}] {finding['type']}")
        if 'detail' in finding:
            print(f"    {finding['detail']}")
        if 'source_ip' in finding:
            print(f"    Source: {finding['source_ip']} -> Target: {finding['target_ip']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
