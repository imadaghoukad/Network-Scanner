#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════╗
║         Azzy's Pro Network Scanner        ║
║         ARP-Based LAN Discovery Tool      ║
╚═══════════════════════════════════════════╝

Usage:
    sudo python3 azzy_scanner.py                    # auto-detect subnet
    sudo python3 azzy_scanner.py -t 192.168.1.0/24
    sudo python3 azzy_scanner.py -t 192.168.1.0/24 --export json
    sudo python3 azzy_scanner.py -t 192.168.1.0/24 --export csv
    sudo python3 azzy_scanner.py -t 192.168.1.0/24 --timeout 3 --verbose
"""

import argparse
import csv
import ipaddress
import json
import logging
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Graceful dependency checks ───────────────────────────────────────────────

def _require(pkg: str, install_name: str = None) -> object:
    """Import a package or exit with a clear install hint."""
    import importlib
    try:
        return importlib.import_module(pkg)
    except ImportError:
        name = install_name or pkg
        print(f"[!] Missing dependency: '{name}'.  Run:  pip install {name}")
        sys.exit(1)

scapy     = _require("scapy.all", "scapy")
rich      = _require("rich", "rich")

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.logging import RichHandler

# ── Logging setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
)
log = logging.getLogger("azzy")

console = Console()

# ── MAC vendor OUI lookup (offline, top ~50 vendors) ─────────────────────────

OUI_TABLE: dict[str, str] = {
    "00:50:56": "VMware",          "00:0c:29": "VMware",
    "00:1a:11": "Google",          "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",    "e4:5f:01": "Raspberry Pi",
    "18:60:24": "Apple",           "ac:bc:32": "Apple",
    "f4:5c:89": "Apple",           "00:17:f2": "Apple",
    "3c:15:c2": "Apple",           "a4:c3:f0": "Google",
    "94:eb:2c": "Google Nest",     "f4:f5:d8": "Google Nest",
    "00:1b:63": "Apple",           "00:25:00": "Apple",
    "08:00:27": "VirtualBox",      "52:54:00": "QEMU/KVM",
    "00:15:5d": "Microsoft Hyper-V","00:03:ff": "Microsoft",
    "00:50:f2": "Microsoft",       "28:d2:44": "NVIDIA",
    "04:42:1a": "NVIDIA",          "00:04:4b": "NVIDIA",
    "1c:69:7a": "Intel",           "a4:c3:f0": "Intel",
    "8c:8d:28": "Intel",           "00:22:fb": "Intel",
    "00:1e:65": "Intel",           "00:1f:3b": "Intel",
    "00:0f:20": "Intel",           "fc:3f:db": "Intel",
    "e8:6a:64": "Samsung",         "8c:71:f8": "Samsung",
    "00:16:32": "Samsung",         "00:21:19": "Samsung",
    "18:29:9e": "Huawei",          "00:e0:fc": "Huawei",
    "70:72:cf": "Huawei",          "cc:53:b5": "Xiaomi",
    "ac:c1:ee": "Xiaomi",          "f8:a2:d6": "Xiaomi",
    "b4:7c:9c": "Cisco",           "00:1b:54": "Cisco",
    "00:13:80": "Cisco",           "c8:9c:1d": "Cisco",
    "00:26:0b": "Cisco",           "00:00:0c": "Cisco",
    "00:1e:f7": "Cisco",           "74:86:7a": "TP-Link",
    "f4:ec:38": "TP-Link",         "50:c7:bf": "TP-Link",
    "ac:84:c6": "TP-Link",         "b0:48:7a": "TP-Link",
    "00:14:d1": "ASUS",            "2c:fd:a1": "ASUS",
    "d8:50:e6": "ASUS",            "04:d4:c4": "ASUS",
    "10:02:b5": "ASUS",            "00:50:ba": "D-Link",
    "1c:7e:e5": "D-Link",          "b8:a3:86": "D-Link",
    "00:1b:11": "D-Link",          "c0:a0:bb": "Netgear",
    "a0:40:a0": "Netgear",         "20:4e:7f": "Netgear",
}

def vendor_lookup(mac: str) -> str:
    """Return manufacturer name from MAC prefix, or 'Unknown'."""
    prefix = mac[:8].lower()
    for oui, name in OUI_TABLE.items():
        if prefix == oui.lower():
            return name
    return "Unknown"

# ── Hostname resolution (non-blocking, with timeout) ─────────────────────────

def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Reverse-DNS lookup with timeout; returns '-' on failure."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"
    finally:
        socket.setdefaulttimeout(old_timeout)

# ── Core ARP scanner ──────────────────────────────────────────────────────────

def arp_scan(ip_range: str, timeout: int = 2) -> list[dict]:
    """
    Send ARP requests to every host in ip_range.
    Returns a list of dicts: {ip, mac, vendor, hostname, latency_ms}.
    """
    try:
        arp_pkt   = scapy.ARP(pdst=ip_range)
        ether_pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet    = ether_pkt / arp_pkt

        t0 = time.perf_counter()
        answered, _ = scapy.srp(packet, timeout=timeout, verbose=False)
        elapsed = time.perf_counter() - t0

        log.debug(f"srp() completed in {elapsed:.2f}s — {len(answered)} response(s)")
        return answered

    except PermissionError:
        console.print(
            "\n[bold red]✗  Permission denied.[/bold red] "
            "Run this tool with [bold]sudo[/bold].\n"
        )
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[bold red]✗  ARP scan failed:[/bold red] {exc}\n")
        sys.exit(1)


def enrich_result(element, dns_timeout: float = 0.5) -> dict:
    """Extract IP/MAC from a scapy answer pair and add vendor + hostname."""
    ip  = element[1].psrc
    mac = element[1].hwsrc
    return {
        "ip":       ip,
        "mac":      mac,
        "vendor":   vendor_lookup(mac),
        "hostname": resolve_hostname(ip, dns_timeout),
    }


def parallel_enrich(answered_list, workers: int = 32) -> list[dict]:
    """Enrich all results concurrently (hostname lookups are the slow part)."""
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(enrich_result, el): el for el in answered_list}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                log.warning(f"Enrichment error: {exc}")
    # Sort by last IP octet for a tidy table
    results.sort(key=lambda d: socket.inet_aton(d["ip"]))
    return results

# ── Network helpers ───────────────────────────────────────────────────────────

def auto_detect_subnet() -> Optional[str]:
    """Detect the local machine's outbound interface IP and derive /24 subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip.rsplit(".", 1)[0] + ".0/24"
    except Exception:
        return None


def validate_target(target: str) -> str:
    """Validate and normalise the target (single IP or CIDR range)."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return str(net)
    except ValueError:
        console.print(f"[bold red]✗  Invalid target:[/bold red] '{target}'")
        sys.exit(1)

# ── Output formatters ─────────────────────────────────────────────────────────

def print_banner(target: str) -> None:
    header = Text()
    header.append("  Azzy's Pro Network Scanner\n", style="bold cyan")
    header.append(f"  Target  : {target}\n", style="white")
    header.append(f"  Started : {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}", style="dim")
    console.print(Panel(header, border_style="cyan", padding=(0, 1)))
    console.print()


def print_table(results: list[dict], elapsed: float) -> None:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
        title=f"[bold cyan]● {len(results)} device(s) found  [dim]({elapsed:.1f}s)[/dim]",
        title_justify="left",
    )
    table.add_column("#",        style="dim",         justify="right", no_wrap=True)
    table.add_column("IP Address",  style="bold white",  no_wrap=True)
    table.add_column("MAC Address", style="yellow",      no_wrap=True)
    table.add_column("Vendor",      style="green")
    table.add_column("Hostname",    style="blue")

    for i, client in enumerate(results, 1):
        hostname_text = (
            Text(client["hostname"], style="blue")
            if client["hostname"] != "-"
            else Text("-", style="dim")
        )
        vendor_text = (
            Text(client["vendor"], style="green")
            if client["vendor"] != "Unknown"
            else Text("Unknown", style="dim")
        )
        table.add_row(
            str(i),
            client["ip"],
            client["mac"],
            vendor_text,
            hostname_text,
        )

    console.print(table)
    console.print()


def export_results(results: list[dict], fmt: str, target: str) -> None:
    """Write results to a JSON or CSV file in the current directory."""
    safe_target = target.replace("/", "_").replace(".", "-")
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename    = f"scan_{safe_target}_{timestamp}.{fmt}"

    if fmt == "json":
        payload = {
            "scan_target": target,
            "scan_time":   datetime.now().isoformat(),
            "hosts_found": len(results),
            "hosts":       results,
        }
        Path(filename).write_text(json.dumps(payload, indent=2))

    elif fmt == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "mac", "vendor", "hostname"])
            writer.writeheader()
            writer.writerows(results)

    console.print(f"[bold green]✓  Results exported →[/bold green] [underline]{filename}[/underline]\n")

# ── CLI ───────────────────────────────────────────────────────────────────────

def get_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="azzy_scanner",
        description="Azzy's Pro Network Scanner — ARP-based LAN discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 azzy_scanner.py\n"
            "  sudo python3 azzy_scanner.py -t 10.0.0.0/24\n"
            "  sudo python3 azzy_scanner.py -t 192.168.1.0/24 --export json\n"
            "  sudo python3 azzy_scanner.py -t 192.168.1.0/24 --timeout 3\n"
        ),
    )
    parser.add_argument(
        "-t", "--target",
        metavar="IP/CIDR",
        help="Target IP or CIDR range (default: auto-detect /24 subnet)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        metavar="SEC",
        help="ARP response timeout in seconds (default: 2)",
    )
    parser.add_argument(
        "--export",
        choices=["json", "csv"],
        metavar="FORMAT",
        help="Export results: json or csv",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=32,
        metavar="N",
        help="Thread pool size for hostname resolution (default: 32)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose / debug logging",
    )
    return parser.parse_args()

# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = get_arguments()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Resolve target
    target = args.target
    if not target:
        target = auto_detect_subnet()
        if not target:
            console.print(
                "[bold red]✗  Could not auto-detect subnet.[/bold red] "
                "Specify one with [bold]-t[/bold]  (e.g., -t 192.168.1.0/24)"
            )
            sys.exit(1)
        console.print(f"[dim]  Auto-detected subnet:[/dim] [cyan]{target}[/cyan]\n")

    target = validate_target(target)
    print_banner(target)

    # Run scan with a live progress bar
    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold cyan"),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning…", total=3)

        # Stage 1: ARP
        progress.update(task, description="Sending ARP packets …", advance=0)
        t_start   = time.perf_counter()
        answered  = arp_scan(target, timeout=args.timeout)
        progress.advance(task, 1)

        # Stage 2: Enrich (vendor + hostname)
        progress.update(task, description="Resolving hostnames & vendors …")
        results = parallel_enrich(answered, workers=args.workers)
        progress.advance(task, 1)

        # Stage 3: Done
        progress.update(task, description="Building report …")
        elapsed = time.perf_counter() - t_start
        progress.advance(task, 1)

    # Print results
    if not results:
        console.print(
            "[bold yellow]⚠  No devices found.[/bold yellow] "
            "Ensure you are connected to a network and try a longer [bold]--timeout[/bold].\n"
        )
        sys.exit(0)

    print_table(results, elapsed)

    # Export if requested
    if args.export:
        export_results(results, args.export, target)


if __name__ == "__main__":
    main()