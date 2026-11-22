#!/usr/bin/env python3
"""Scan TCP ports and check a few common security exposures."""
import argparse
import concurrent.futures
import json
import socket
import ssl
import sys

COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8000,8080,8443,11211,27017"
HTTP_PORTS = {80, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443}
SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP", 8080: "HTTP", 8443: "HTTPS", 11211: "Memcached", 27017: "MongoDB"}


def parse_ports(value):
    ports = set()
    try:
        for part in value.split(","):
            if not part:
                raise ValueError("empty port")
            bounds = part.split("-")
            if len(bounds) > 2:
                raise ValueError("invalid range")
            start = int(bounds[0])
            end = int(bounds[-1])
            if not 1 <= start <= end <= 65535:
                raise ValueError("port out of range")
            ports.update(range(start, end + 1))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use ports from 1 to 65535, e.g. 22,80,8000-8010") from exc
    return sorted(ports)


def resolve(target):
    # Resolve once so every connection uses the same address.
    results = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    if not results:
        raise OSError("No address found")
    return results[0][4][0]


def is_open(address, port, timeout):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def request_bytes(address, port, timeout, payload, tls_host=None):
    with socket.create_connection((address, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        def exchange(conn):
            conn.sendall(payload)
            result = bytearray()
            delimiter = b"\r\n\r\n" if payload.startswith(b"HEAD ") else b"\r\n"
            while len(result) < 16384 and delimiter not in result:
                try:
                    chunk = conn.recv(min(4096, 16384 - len(result)))
                except socket.timeout:
                    break
                if not chunk:
                    break
                result.extend(chunk)
            return bytes(result)
        if tls_host:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=tls_host) as conn:
                return exchange(conn)
        return exchange(raw)


def issue(port, severity, name, evidence, recommendation):
    return {"port": port, "severity": severity, "finding": name, "evidence": evidence, "recommendation": recommendation}


def inspect(address, hostname, port, timeout):
    findings = []
    if port == 23:
        findings.append(issue(port, "info", "Telnet port reachable", "TCP port 23 is reachable; service identity was not verified.", "Disable Telnet or restrict access and use SSH."))
    if port == 6379:
        try:
            response = request_bytes(address, port, timeout, b"*1\r\n$4\r\nPING\r\n")
            if response.startswith(b"+PONG\r\n"):
                findings.append(issue(port, "high", "Redis responds without authentication", "+PONG received without credentials.", "Restrict network access and require Redis authentication."))
        except OSError:
            pass
    if port == 11211:
        try:
            response = request_bytes(address, port, timeout, b"stats\r\n")
            if response.startswith(b"STAT "):
                findings.append(issue(port, "high", "Memcached statistics exposed", "Server returned statistics without authentication.", "Restrict access to trusted hosts and disable external exposure."))
        except OSError:
            pass
    if port in HTTP_PORTS | HTTPS_PORTS:
        # No redirects or active exploits: a single HEAD request to the selected host.
        try:
            host_header = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname.encode("idna").decode("ascii")
            payload = f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n".encode("ascii")
            response = request_bytes(address, port, timeout, payload, hostname if port in HTTPS_PORTS else None)
            if not response.startswith(b"HTTP/") or b"\r\n\r\n" not in response:
                return findings
            lines = response.decode("iso-8859-1").split("\r\n")
            fields = {line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip() for line in lines[1:] if ":" in line}
            if port in HTTP_PORTS:
                findings.append(issue(port, "info", "Unencrypted HTTP available", lines[0], "Redirect to HTTPS and avoid sending sensitive data over HTTP."))
            elif "strict-transport-security" not in fields:
                findings.append(issue(port, "info", "HSTS header missing", lines[0], "Consider Strict-Transport-Security after confirming HTTPS is configured everywhere."))
            if "x-content-type-options" not in fields:
                findings.append(issue(port, "info", "X-Content-Type-Options header missing", lines[0], "Consider sending X-Content-Type-Options: nosniff."))
        except ssl.SSLCertVerificationError as exc:
            findings.append(issue(port, "medium", "TLS certificate verification failed", exc.verify_message, "Install a valid certificate trusted for the target hostname."))
        except (OSError, ssl.SSLError, UnicodeError):
            pass
    return findings


def scan(target, ports, timeout=1.0, workers=64, checks=True):
    address = resolve(target)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        opened = sorted(port for port, status in zip(ports, executor.map(lambda port: is_open(address, port, timeout), ports)) if status)
        results = list(executor.map(lambda port: inspect(address, target, port, timeout), opened)) if checks else []
    return {"target": target, "address": address, "open_ports": [{"port": p, "service_hint": SERVICES.get(p, "unknown")} for p in opened], "findings": [item for result in results for item in result]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan TCP ports and check a few common exposures on a host you are authorized to test.")
    parser.add_argument("target", help="A hostname or IP address")
    parser.add_argument("--ports", type=parse_ports, default=parse_ports(COMMON_PORTS), help="Ports and ranges, e.g. 22,80,443,8000-8010")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per connection in seconds (default: 1)")
    parser.add_argument("--workers", type=int, default=64, help="Concurrent connections (1–256, default: 64)")
    parser.add_argument("--ports-only", action="store_true", help="Skip application-level exposure checks")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 30 or not 1 <= args.workers <= 256:
        parser.error("timeout must be > 0 and <= 30; workers must be from 1 to 256")
    try:
        report = scan(args.target, args.ports, args.timeout, args.workers, not args.ports_only)
    except (OSError, UnicodeError) as exc:
        print(f"Could not resolve target: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Target: {report['target']} ({report['address']})")
        print("Open TCP ports:")
        for item in report["open_ports"]:
            print(f"  {item['port']}/tcp  {item['service_hint']} (port-based hint)")
        if not report["open_ports"]:
            print("  None found")
        if not args.ports_only:
            print("\nFindings:")
            for item in report["findings"]:
                print(f"  [{item['severity'].upper()}] {item['port']}: {item['finding']} — {item['evidence']}\n    {item['recommendation']}")
            if not report["findings"]:
                print("  None detected by these limited checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
