"""Sentinel-Lab - Hybrid (Windows/Linux) security audit and remediation tool.

Entry point:
    python main.py
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from core import detect_os, get_logger, is_admin, require_admin
from modules import (
    FirewallManager, FirewallStatus, NetworkScanner, OpenPort, Remediator,
)
from modules.network_scanner import ScanResult

BANNER = r"""
  ____             _   _            _       _          _
 / ___|  ___ _ __ | |_(_)_ __   ___| |     | |    __ _| |__
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |_____| |   / _` | '_ \
  ___) |  __/ | | | |_| | | | |  __/ |_____| |__| (_| | |_) |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|     |_____\__,_|_.__/
                           hybrid audit & remediation console
"""


def _resolve_config_path(cli_path: str | None) -> Path:
    if cli_path:
        return Path(cli_path).expanduser().resolve()
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent
    return base / "config" / "threats.yaml"


def load_threat_db(path: Path, console: Console, logger) -> dict:
    if not path.exists():
        console.print(f"[yellow]Config not found at {path}; using empty threat DB.[/yellow]")
        logger.warning("threats.yaml not found at %s", path)
        return {"threat_ports": [], "suspicious_ips": [], "protected_processes": []}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except yaml.YAMLError as err:
        logger.error("Invalid YAML in %s: %s", path, err)
        console.print(f"[red]Invalid YAML in {path}: {err}[/red]")
        return {"threat_ports": [], "suspicious_ips": [], "protected_processes": []}
    data.setdefault("threat_ports", [])
    data.setdefault("suspicious_ips", [])
    data.setdefault("protected_processes", [])
    logger.info("Loaded threat DB: %d ports, %d IPs, %d protected processes",
                len(data["threat_ports"]), len(data["suspicious_ips"]),
                len(data["protected_processes"]))
    return data


def extract_port_numbers(threat_entries: list) -> list[int]:
    numbers: list[int] = []
    for entry in threat_entries:
        if isinstance(entry, dict) and "port" in entry:
            try:
                numbers.append(int(entry["port"]))
            except (TypeError, ValueError):
                continue
        else:
            try:
                numbers.append(int(entry))
            except (TypeError, ValueError):
                continue
    return numbers


def threat_reason_for(port: int, threat_entries: list) -> str:
    for entry in threat_entries:
        if isinstance(entry, dict) and int(entry.get("port", -1)) == port:
            return str(entry.get("reason") or entry.get("name") or "high-risk port")
    return "high-risk port"


def print_banner(console: Console) -> None:
    console.print(Text(BANNER, style="bold cyan"))


def print_system_panel(console: Console) -> None:
    os_info = detect_os()
    admin = "[green]YES[/green]" if is_admin() else "[red]NO[/red]"
    pretty_family = {
        "windows": "Windows",
        "linux": "Linux",
        "macos": "macOS (Darwin)",
    }.get(os_info.family, os_info.family)
    content = (
        f"OS family   : [bold]{pretty_family}[/bold]\n"
        f"Release     : {os_info.release}\n"
        f"Machine     : {os_info.machine}\n"
        f"Privileges  : {admin}"
    )
    console.print(Panel(content, title="System", border_style="cyan", expand=False))


def print_firewall_panel(console: Console, status: FirewallStatus) -> None:
    color = "green" if status.active else "red"
    header = "OK" if status.active else "CRITICAL"
    lines = [
        f"Backend : [bold]{status.backend}[/bold]",
        f"Status  : [{color}]{header}[/{color}]",
    ]
    if status.profiles:
        for profile, enabled in status.profiles.items():
            mark = "[green]on[/green]" if enabled else "[red]off[/red]"
            lines.append(f"  - {profile:<8}: {mark}")
    if not status.active:
        lines.append("[red]Firewall is DISABLED - system is exposed.[/red]")
    console.print(Panel("\n".join(lines), title="Firewall",
                        border_style=color, expand=False))


def build_ports_table(result: ScanResult) -> Table:
    secured = len(result.secured)
    table = Table(
        title=f"Open ports ({len(result.ports)} total | {len(result.threats)} threats | {secured} protected)",
        header_style="bold white on blue",
        show_lines=False,
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("Status")
    table.add_column("PID", justify="right")
    table.add_column("Process")
    table.add_column("Executable", overflow="fold")
    table.add_column("Risk")

    for idx, port in enumerate(result.ports, start=1):
        if port.is_threat:
            row_style = "bold red"
            status_label = f"[red]{port.status}[/red]"
            risk = "[red]THREAT[/red]"
        elif port.is_secured:
            row_style = "bold green"
            status_label = "[green]SECURED[/green]"
            risk = "[green]PROTECTED[/green]"
        else:
            row_style = None
            status_label = port.status
            risk = "[green]ok[/green]"
        table.add_row(
            str(idx),
            str(port.port),
            port.protocol,
            port.local_address,
            port.remote_address or "-",
            status_label,
            str(port.pid) if port.pid else "-",
            port.process_name or "unknown",
            port.process_exe or "-",
            risk,
            style=row_style,
        )
    return table


def perform_scan(scanner: NetworkScanner, console: Console) -> ScanResult:
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Enumerating sockets...", total=None)
        result = scanner.scan()
        progress.update(task, completed=1, total=1)
    return result


def interactive_remediation(
    console: Console,
    logger,
    result: ScanResult,
    remediator: Remediator,
    protected_processes: set[str],
) -> None:
    if not result.threats:
        console.print("[green]No threats flagged - nothing to remediate.[/green]")
        return

    console.print(Panel(
        "Interactive remediation mode. Select a flagged port to act on, "
        "or type 'q' to quit.",
        border_style="yellow", title="Remediation",
    ))

    while True:
        threat_table = Table(header_style="bold yellow")
        threat_table.add_column("Idx", justify="right")
        threat_table.add_column("Port", justify="right")
        threat_table.add_column("Proto")
        threat_table.add_column("PID", justify="right")
        threat_table.add_column("Process")
        threat_table.add_column("Reason")
        for idx, port in enumerate(result.threats, start=1):
            threat_table.add_row(
                str(idx), str(port.port), port.protocol,
                str(port.pid) if port.pid else "-",
                port.process_name or "unknown",
                port.threat_reason or "-",
            )
        console.print(threat_table)

        choice = Prompt.ask(
            "Select a threat index (or [b]q[/b] to quit)",
            default="q",
        ).strip().lower()
        if choice in {"q", "quit", "exit", ""}:
            break
        if not choice.isdigit():
            console.print("[red]Invalid selection.[/red]")
            continue
        idx = int(choice)
        if not (1 <= idx <= len(result.threats)):
            console.print("[red]Index out of range.[/red]")
            continue

        target = result.threats[idx - 1]
        _handle_single_threat(console, logger, target, remediator, protected_processes)


def _handle_single_threat(
    console: Console,
    logger,
    target: OpenPort,
    remediator: Remediator,
    protected_processes: set[str],
) -> None:
    console.print(Panel(
        f"Port     : [bold]{target.port}/{target.protocol}[/bold]\n"
        f"PID      : {target.pid or '-'}\n"
        f"Process  : {target.process_name or 'unknown'}\n"
        f"Executable: {target.process_exe or '-'}\n"
        f"Reason   : {target.threat_reason or '-'}",
        title=f"Threat on port {target.port}", border_style="red",
    ))

    actions = [
        ("1", "Terminate the associated process"),
        ("2", "Add a firewall rule to block this port"),
        ("3", "Skip"),
    ]
    for key, label in actions:
        console.print(f"  [bold]{key}[/bold]. {label}")

    action = Prompt.ask("Action", choices=["1", "2", "3"], default="3")

    if action == "1":
        if not target.pid:
            console.print("[yellow]No PID associated with this port.[/yellow]")
            return
        if (target.process_name or "") in protected_processes:
            console.print(
                f"[red]Refusing to terminate protected process "
                f"{target.process_name}.[/red]"
            )
            logger.warning("Protected process %s shielded from remediation",
                           target.process_name)
            return
        if not Confirm.ask(
            f"Really terminate PID {target.pid} ({target.process_name})?",
            default=False,
        ):
            return
        outcome = remediator.kill_process(target.pid)
        _report(console, outcome.success, outcome.message)

    elif action == "2":
        if not Confirm.ask(
            f"Add firewall rule to block {target.protocol}/{target.port}?",
            default=False,
        ):
            return
        outcome = remediator.close_port(target.port, target.protocol)
        _report(console, outcome.success, outcome.message)


def _report(console: Console, ok: bool, message: str) -> None:
    style = "green" if ok else "red"
    console.print(f"[{style}]{message}[/{style}]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-lab",
        description="Sentinel-Lab: hybrid Windows/Linux security audit tool.",
    )
    parser.add_argument("--config", "-c", help="Path to threats.yaml")
    parser.add_argument("--no-udp", action="store_true",
                        help="Skip UDP enumeration")
    parser.add_argument("--no-interactive", action="store_true",
                        help="Run audit only; skip the remediation prompt")
    parser.add_argument("--no-admin-check", action="store_true",
                        help="Skip the admin/root privilege check (not recommended)")
    parser.add_argument("--debug", action="store_true",
                        help="Print scanner/firewall debug output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    logger = get_logger("sentinel")

    print_banner(console)
    logger.info("=== Sentinel-Lab session started ===")

    if not is_admin():
        console.print(
            Panel(
                "[bold red]ADMIN RIGHTS REQUIRED[/bold red]\n\n"
                "Sentinel-Lab must run with elevated privileges to:\n"
                "  • Enumerate all network connections\n"
                "  • Query firewall rules\n"
                "  • Apply remediation actions\n\n"
                "Please restart as:\n"
                "  Windows: Right-click → Run as Administrator\n"
                "  Linux  : sudo python3 main.py\n"
                "  macOS  : sudo python3 main.py",
                border_style="red",
                title="ACCESS DENIED",
            )
        )
        logger.critical("Admin check failed; user lacks required privileges")
        return 2

    logger.info("Admin privileges verified")

    try:
        print_system_panel(console)
    except RuntimeError as err:
        console.print(f"[red]{err}[/red]")
        logger.error("OS detection failed: %s", err)
        return 1

    config_path = _resolve_config_path(args.config)
    threat_db = load_threat_db(config_path, console, logger)
    threat_ports = extract_port_numbers(threat_db.get("threat_ports", []))
    suspicious_ips = [str(ip) for ip in threat_db.get("suspicious_ips", [])]
    protected_processes = {str(p) for p in threat_db.get("protected_processes", [])}

    firewall = FirewallManager()
    try:
        fw_status = firewall.status()
    except Exception as err:
        logger.exception("Firewall status check failed: %s", err)
        fw_status = FirewallStatus("error", False, str(err))
    print_firewall_panel(console, fw_status)
    if not fw_status.active:
        logger.critical("Firewall is INACTIVE (backend=%s)", fw_status.backend)

    scanner = NetworkScanner(
        threat_ports=threat_ports,
        suspicious_ips=suspicious_ips,
        auto_fetch_firewall=True,
        debug=args.debug,
    )
    try:
        result = perform_scan(scanner, console)
    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted by user.[/yellow]")
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as err:
        logger.exception("Scan failed: %s", err)
        console.print(f"[red]Scan failed: {err}[/red]")
        return 1

    for port in result.ports:
        if port.is_threat and not port.threat_reason:
            port.threat_reason = threat_reason_for(port.port, threat_db["threat_ports"])

    console.print(build_ports_table(result))

    if not result.threats:
        console.print("[green]No high-risk ports detected.[/green]")
    else:
        console.print(
            f"[red]{len(result.threats)} port(s) flagged as threats.[/red]"
        )

    if args.no_interactive:
        logger.info("Non-interactive mode; skipping remediation prompt")
        return 0

    try:
        if Confirm.ask("Enter interactive remediation mode?", default=False):
            remediator = Remediator(firewall=firewall)
            interactive_remediation(
                console, logger, result, remediator, protected_processes
            )

            if Confirm.ask("\n[cyan]Run a fresh scan to verify remediation?[/cyan]", default=True):
                console.print("[yellow]Waiting 1 second for firewall to sync...[/yellow]")
                time.sleep(1)
                scanner.blocked_ports.clear()
                try:
                    result = perform_scan(scanner, console)
                    for port in result.ports:
                        if port.is_threat and not port.threat_reason:
                            port.threat_reason = threat_reason_for(port.port, threat_db["threat_ports"])
                    console.print("\n[bold cyan]=== VERIFICATION SCAN ===[/bold cyan]\n")
                    console.print(build_ports_table(result))
                    if not result.threats:
                        console.print("[green]All threats have been remediated or protected.[/green]")
                    else:
                        console.print(f"[yellow]{len(result.threats)} threat(s) remain.[/yellow]")
                except Exception as err:
                    logger.exception("Verification scan failed: %s", err)
                    console.print(f"[red]Verification scan failed: {err}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Session interrupted.[/yellow]")
        logger.warning("Remediation session interrupted by user")
        return 130

    logger.info("=== Sentinel-Lab session ended ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
