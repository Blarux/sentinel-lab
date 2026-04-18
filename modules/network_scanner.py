from __future__ import annotations

import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Iterable

import psutil

from core import get_logger


@dataclass
class OpenPort:
    port: int
    protocol: str
    local_address: str
    remote_address: str
    status: str
    pid: int | None
    process_name: str | None
    process_exe: str | None
    is_threat: bool = False
    threat_reason: str = ""
    is_secured: bool = False
    secured_by: str = ""

    def as_row(self) -> list[str]:
        pid_str = str(self.pid) if self.pid else "-"
        return [
            str(self.port),
            self.protocol,
            self.local_address,
            self.remote_address or "-",
            self.status,
            pid_str,
            self.process_name or "unknown",
            self.process_exe or "-",
        ]


@dataclass
class ScanResult:
    ports: list[OpenPort] = field(default_factory=list)
    blocked_ports: list[int] = field(default_factory=list)

    @property
    def threats(self) -> list[OpenPort]:
        return [p for p in self.ports if p.is_threat]

    @property
    def secured(self) -> list[OpenPort]:
        return [p for p in self.ports if p.is_secured]


class NetworkScanner:
    LISTEN_STATUSES = {"LISTEN", "NONE"}
    SENTINEL_RULE_PREFIX = "Sentinel"

    def __init__(self, threat_ports: Iterable[int] | None = None,
                 suspicious_ips: Iterable[str] | None = None,
                 blocked_ports: Iterable[int] | None = None,
                 auto_fetch_firewall: bool = True,
                 debug: bool = False) -> None:
        self.threat_ports = set(int(p) for p in (threat_ports or []))
        self.suspicious_ips = set((suspicious_ips or []))
        self.blocked_ports: set[int] = set(int(p) for p in (blocked_ports or []))
        self.auto_fetch_firewall = auto_fetch_firewall
        self.debug = debug
        self.logger = get_logger("sentinel.scanner")
        self._is_windows = platform.system().lower() == "windows"

    def scan(self, include_udp: bool = True) -> ScanResult:
        if self.auto_fetch_firewall:
            fetched = self.fetch_sentinel_blocked_ports()
            if fetched:
                self.blocked_ports.update(fetched)

        self.logger.info("Scanner blocked_ports=%s", sorted(self.blocked_ports))
        if self.debug:
            print(f"[DEBUG] Sentinel blocked ports: {sorted(self.blocked_ports)}")

        result = ScanResult(blocked_ports=sorted(self.blocked_ports))
        kinds = ["tcp"] + (["udp"] if include_udp else [])

        for kind in kinds:
            try:
                connections = psutil.net_connections(kind=kind)
            except (psutil.AccessDenied, PermissionError) as err:
                self.logger.warning("Access denied enumerating %s: %s", kind, err)
                continue
            except Exception as err:
                self.logger.exception("Unexpected error enumerating %s: %s", kind, err)
                continue

            for conn in connections:
                port = self._extract_listening_port(conn, kind)
                if port is None:
                    continue
                open_port = self._build_open_port(conn, kind, port)
                result.ports.append(open_port)

        result.ports.sort(key=lambda p: (not p.is_threat, not p.is_secured, p.port))
        self.logger.info(
            "Scan complete: %d ports listed, %d threats, %d secured",
            len(result.ports), len(result.threats), len(result.secured),
        )
        return result

    def fetch_sentinel_blocked_ports(self) -> set[int]:
        if self._is_windows:
            ports = self._fetch_via_powershell()
            if ports is None:
                ports = self._fetch_via_netsh()
            return ports or set()
        return self._fetch_via_ufw()

    def _fetch_via_powershell(self) -> set[int] | None:
        if not shutil.which("powershell") and not shutil.which("powershell.exe"):
            return None

        script = (
            "Get-NetFirewallRule -Action Block -Enabled True "
            f"| Where-Object {{ $_.DisplayName -like '{self.SENTINEL_RULE_PREFIX}*' "
            f"-or $_.Name -like '{self.SENTINEL_RULE_PREFIX}*' }} "
            "| Get-NetFirewallPortFilter "
            "| Select-Object -ExpandProperty LocalPort"
        )
        cmd = ["powershell", "-NoProfile", "-Command", script]

        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False,
            )
        except FileNotFoundError:
            self.logger.debug("PowerShell not found; falling back to netsh")
            return None
        except subprocess.TimeoutExpired as err:
            self.logger.warning("PowerShell firewall query timed out: %s", err)
            return None

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            if "Access is denied" in stderr or "PermissionDenied" in stderr:
                self.logger.error(
                    "Firewall enumeration denied - admin privileges required. stderr=%s",
                    stderr,
                )
            else:
                self.logger.warning(
                    "PowerShell firewall query failed (rc=%s): %s",
                    completed.returncode, stderr,
                )
            return None

        ports = self._parse_powershell_port_output(completed.stdout or "")
        self.logger.info("PowerShell detected %d Sentinel-blocked port(s)", len(ports))
        if self.debug:
            print(f"[DEBUG] PowerShell Sentinel ports: {sorted(ports)}")
        return ports

    @staticmethod
    def _parse_powershell_port_output(output: str) -> set[int]:
        ports: set[int] = set()
        for raw in output.splitlines():
            token = raw.strip()
            if not token or token.lower() == "any":
                continue
            for piece in re.split(r"[,\s]+", token):
                if not piece:
                    continue
                if "-" in piece:
                    try:
                        start, end = piece.split("-", 1)
                        for p in range(int(start), int(end) + 1):
                            ports.add(p)
                    except ValueError:
                        continue
                else:
                    try:
                        ports.add(int(piece))
                    except ValueError:
                        continue
        return ports

    def _fetch_via_netsh(self) -> set[int]:
        if not shutil.which("netsh") and not shutil.which("netsh.exe"):
            self.logger.warning("netsh not available; cannot enumerate firewall rules")
            return set()

        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False,
            )
        except FileNotFoundError:
            return set()
        except subprocess.TimeoutExpired as err:
            self.logger.warning("netsh firewall query timed out: %s", err)
            return set()

        output = completed.stdout or ""
        stderr = (completed.stderr or "").strip()

        if completed.returncode != 0:
            if "elevation" in stderr.lower() or "denied" in stderr.lower():
                self.logger.error(
                    "netsh enumeration requires Administrator privileges. stderr=%s",
                    stderr,
                )
            else:
                self.logger.warning(
                    "netsh failed (rc=%s): %s", completed.returncode, stderr,
                )
            return set()

        ports = self._parse_netsh_rules(output)
        self.logger.info("netsh detected %d Sentinel-blocked port(s)", len(ports))
        if self.debug:
            print(f"[DEBUG] netsh Sentinel ports: {sorted(ports)}")
        return ports

    def _parse_netsh_rules(self, output: str) -> set[int]:
        blocks = re.split(r"(?mi)^\s*Rule Name:\s*", output)
        ports: set[int] = set()

        for block in blocks[1:]:
            first_line, _, rest = block.partition("\n")
            rule_name = first_line.strip()
            if not rule_name.startswith(self.SENTINEL_RULE_PREFIX):
                continue

            action_match = re.search(r"(?mi)^\s*Action:\s*(\S+)", rest)
            if action_match and action_match.group(1).lower() != "block":
                continue

            enabled_match = re.search(r"(?mi)^\s*Enabled:\s*(\S+)", rest)
            if enabled_match and enabled_match.group(1).lower() not in {"yes", "oui"}:
                continue

            for lp_match in re.finditer(r"(?mi)^\s*LocalPort:\s*(.+)$", rest):
                local_port = lp_match.group(1).strip()
                if not local_port or local_port.lower() == "any":
                    continue
                for piece in re.split(r"[,\s]+", local_port):
                    if not piece:
                        continue
                    if "-" in piece:
                        try:
                            start, end = piece.split("-", 1)
                            for p in range(int(start), int(end) + 1):
                                ports.add(p)
                        except ValueError:
                            continue
                    else:
                        try:
                            ports.add(int(piece))
                        except ValueError:
                            continue

            if self.debug:
                print(f"[DEBUG] Matched Sentinel rule: '{rule_name}'")

        return ports

    def _fetch_via_ufw(self) -> set[int]:
        if not shutil.which("ufw"):
            return set()
        try:
            completed = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True,
                timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.warning("ufw query failed: %s", err)
            return set()

        if completed.returncode != 0:
            stderr = (completed.stderr or "").lower()
            if "permission" in stderr or "root" in stderr:
                self.logger.error("ufw enumeration requires root privileges.")
            return set()

        ports: set[int] = set()
        pattern = re.compile(r"^\s*(\d+)(?:/(?:tcp|udp))?\s+DENY", re.IGNORECASE | re.MULTILINE)
        for match in pattern.finditer(completed.stdout or ""):
            ports.add(int(match.group(1)))
        return ports

    def _extract_listening_port(self, conn, kind: str) -> int | None:
        if not conn.laddr:
            return None
        if kind == "tcp" and conn.status not in self.LISTEN_STATUSES:
            return None
        try:
            return int(conn.laddr.port)
        except (AttributeError, ValueError):
            return None

    def _build_open_port(self, conn, kind: str, port: int) -> OpenPort:
        pid = conn.pid
        process_name, process_exe = self._resolve_process(pid)
        local = f"{conn.laddr.ip}:{conn.laddr.port}"
        remote = ""
        if conn.raddr:
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"

        is_threat = False
        reason = ""
        if port in self.threat_ports:
            is_threat = True
            reason = f"port {port} listed as high-risk"
        elif conn.raddr and conn.raddr.ip in self.suspicious_ips:
            is_threat = True
            reason = f"remote IP {conn.raddr.ip} flagged as suspicious"

        is_secured = False
        secured_by = ""
        if is_threat and port in self.blocked_ports:
            is_secured = True
            is_threat = False
            secured_by = "Sentinel firewall rule"
            if self.debug:
                print(f"[DEBUG] Port {port}/{kind.upper()} → PROTECTED "
                      f"(threat overridden by firewall rule)")

        return OpenPort(
            port=port,
            protocol=kind.upper(),
            local_address=local,
            remote_address=remote,
            status=conn.status or "-",
            pid=pid,
            process_name=process_name,
            process_exe=process_exe,
            is_threat=is_threat,
            threat_reason=reason,
            is_secured=is_secured,
            secured_by=secured_by,
        )

    def _resolve_process(self, pid: int | None) -> tuple[str | None, str | None]:
        if not pid:
            return None, None
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                try:
                    exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    exe = None
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None, None

    @staticmethod
    def resolve_service(port: int, protocol: str = "tcp") -> str:
        try:
            return socket.getservbyport(int(port), protocol.lower())
        except OSError:
            return "unknown"
