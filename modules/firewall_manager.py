from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from core import detect_os, get_logger


@dataclass
class FirewallStatus:
    backend: str
    active: bool
    raw_output: str
    profiles: dict[str, bool] = field(default_factory=dict)

    @property
    def severity(self) -> str:
        return "OK" if self.active else "CRITICAL"


@dataclass
class BlockedPort:
    port: int
    protocol: str
    rule_name: str


class FirewallManager:
    def __init__(self) -> None:
        self.logger = get_logger("sentinel.firewall")
        self.os_info = detect_os()

    def status(self) -> FirewallStatus:
        if self.os_info.is_windows:
            return self._status_windows()
        if self.os_info.is_macos:
            return self._status_macos()
        return self._status_linux()

    def block_port(self, port: int, protocol: str = "TCP") -> bool:
        port = int(port)
        protocol = protocol.upper()
        if self.os_info.is_windows:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Sentinel-Block-{protocol}-{port}",
                "dir=in", "action=block",
                f"protocol={protocol}", f"localport={port}",
            ]
            return self._run_action(cmd, f"block port {port}/{protocol}")

        if self.os_info.is_macos:
            return self._block_port_macos(port, protocol)

        if not shutil.which("ufw"):
            self.logger.error("ufw not available; cannot block port %s", port)
            return False
        cmd = ["ufw", "deny", f"{port}/{protocol.lower()}"]
        return self._run_action(cmd, f"block port {port}/{protocol}")

    def block_ip(self, ip: str) -> bool:
        if self.os_info.is_windows:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=Sentinel-Block-IP-{ip}",
                "dir=in", "action=block",
                f"remoteip={ip}",
            ]
            return self._run_action(cmd, f"block ip {ip}")

        if self.os_info.is_macos:
            return self._block_ip_macos(ip)

        if not shutil.which("ufw"):
            self.logger.error("ufw not available; cannot block ip %s", ip)
            return False
        cmd = ["ufw", "deny", "from", ip]
        return self._run_action(cmd, f"block ip {ip}")

    def get_blocked_ports(self) -> list[BlockedPort]:
        if self.os_info.is_windows:
            return self._get_blocked_ports_windows()
        if self.os_info.is_macos:
            return self._get_blocked_ports_macos()
        return self._get_blocked_ports_linux()

    def _get_blocked_ports_windows(self) -> list[BlockedPort]:
        try:
            completed = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=all", "dir=in", "action=block"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.warning("Failed to enumerate Windows firewall rules: %s", err)
            return []

        output = completed.stdout or ""
        blocked = []
        rule_name = None
        port = None
        protocol = None
        all_rules = []

        for line in output.splitlines():
            line = line.strip()
            if line.lower().startswith("rule name:"):
                if rule_name and port and protocol:
                    all_rules.append((rule_name, port, protocol))
                rule_name = line.split(":", 1)[1].strip()
                port = None
                protocol = None
            elif line.lower().startswith("localport:") and rule_name:
                port_str = line.split(":", 1)[1].strip()
                if port_str and port_str not in {"any", "-"}:
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = None
            elif line.lower().startswith("protocol:") and rule_name:
                protocol = line.split(":", 1)[1].strip().upper()

        if rule_name and port and protocol:
            all_rules.append((rule_name, port, protocol))

        for rule_name, port, protocol in all_rules:
            if "Sentinel" in rule_name:
                blocked.append(BlockedPort(port=port, protocol=protocol, rule_name=rule_name))
                print(f"[DEBUG] Found Sentinel rule: {rule_name} | port={port}/{protocol}")

        self.logger.debug("Windows firewall: found %d Sentinel block rules out of %d total",
                          len(blocked), len(all_rules))
        print(f"[DEBUG] All parsed rules: {all_rules}")
        return blocked

    def _get_blocked_ports_linux(self) -> list[BlockedPort]:
        if not shutil.which("ufw"):
            return []
        try:
            completed = subprocess.run(
                ["ufw", "status", "numbered"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.warning("Failed to enumerate ufw rules: %s", err)
            return []

        output = completed.stdout or ""
        blocked = []
        port_proto_pattern = re.compile(r"(\d+)/(tcp|udp)", re.IGNORECASE)

        for line in output.splitlines():
            if "DENY IN" in line and "Anywhere" in line:
                match = port_proto_pattern.search(line)
                if match:
                    port = int(match.group(1))
                    protocol = match.group(2).upper()
                    blocked.append(BlockedPort(port=port, protocol=protocol, rule_name="ufw"))

        self.logger.debug("Linux firewall: found %d deny rules", len(blocked))
        return blocked

    def _status_windows(self) -> FirewallStatus:
        try:
            completed = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.error("netsh unavailable or slow: %s", err)
            return FirewallStatus("netsh", False, str(err))

        output = completed.stdout or completed.stderr or ""
        profiles: dict[str, bool] = {}
        current = None
        for line in output.splitlines():
            line = line.strip()
            if line.endswith("Profile Settings:"):
                current = line.split()[0].lower()
            elif current and line.lower().startswith("state"):
                profiles[current] = "on" in line.lower()
                current = None

        active = bool(profiles) and all(profiles.values())
        return FirewallStatus("netsh", active, output, profiles)

    def _status_linux(self) -> FirewallStatus:
        if shutil.which("ufw"):
            return self._status_via_ufw()
        if shutil.which("firewall-cmd"):
            return self._status_via_firewalld()
        if shutil.which("iptables"):
            return self._status_via_iptables()
        self.logger.warning("No known firewall backend detected on Linux")
        return FirewallStatus("none", False, "No firewall backend found")

    def _status_via_ufw(self) -> FirewallStatus:
        completed = subprocess.run(
            ["ufw", "status"], capture_output=True, text=True, timeout=10, check=False
        )
        output = completed.stdout or completed.stderr or ""
        active = "status: active" in output.lower()
        return FirewallStatus("ufw", active, output)

    def _status_via_firewalld(self) -> FirewallStatus:
        completed = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True,
            timeout=10, check=False,
        )
        output = (completed.stdout or completed.stderr or "").strip()
        active = output.lower() == "running"
        return FirewallStatus("firewalld", active, output)

    def _status_via_iptables(self) -> FirewallStatus:
        completed = subprocess.run(
            ["iptables", "-S"], capture_output=True, text=True, timeout=10, check=False,
        )
        output = completed.stdout or ""
        rules = [ln for ln in output.splitlines() if ln and not ln.startswith("-P")]
        active = len(rules) > 0
        return FirewallStatus("iptables", active, output)

    # ------------------------------------------------------------------
    # macOS backend (Application Layer Firewall + pfctl)
    # ------------------------------------------------------------------
    _ALF_STATES = {0: "off", 1: "on (allow signed)", 2: "on (block all)"}
    _PF_ANCHOR = "com.sentinel-lab"

    def _status_macos(self) -> FirewallStatus:
        try:
            completed = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.error("defaults read failed: %s", err)
            return FirewallStatus("alf", False, str(err))

        raw = (completed.stdout or "").strip()
        output = raw or (completed.stderr or "").strip()

        try:
            state = int(raw)
        except ValueError:
            state = -1

        active = state in (1, 2)
        profiles = {"alf": active}

        if shutil.which("pfctl"):
            try:
                pf_completed = subprocess.run(
                    ["pfctl", "-s", "info"], capture_output=True, text=True,
                    timeout=10, check=False,
                )
                pf_output = pf_completed.stdout or ""
                pf_active = "Status: Enabled" in pf_output
                profiles["pf"] = pf_active
                active = active or pf_active
                output = f"alf={self._ALF_STATES.get(state, 'unknown')}; pf={'on' if pf_active else 'off'}"
            except (FileNotFoundError, subprocess.TimeoutExpired) as err:
                self.logger.debug("pfctl status check failed: %s", err)

        return FirewallStatus("alf+pf", active, output, profiles)

    def _block_port_macos(self, port: int, protocol: str) -> bool:
        if not shutil.which("pfctl"):
            self.logger.error("pfctl not found; cannot block port %s/%s", port, protocol)
            return False
        rule = f'block in quick proto {protocol.lower()} from any to any port {port}'
        return self._apply_pf_anchor_rule(rule, f"block port {port}/{protocol}")

    def _block_ip_macos(self, ip: str) -> bool:
        if not shutil.which("pfctl"):
            self.logger.error("pfctl not found; cannot block ip %s", ip)
            return False
        rule = f'block in quick from {ip} to any'
        return self._apply_pf_anchor_rule(rule, f"block ip {ip}")

    def _apply_pf_anchor_rule(self, rule: str, description: str) -> bool:
        import tempfile

        existing = self._read_pf_anchor()
        combined = (existing + "\n" + rule).strip() + "\n"

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".pf", delete=False) as fh:
                fh.write(combined)
                tmp_path = fh.name
        except OSError as err:
            self.logger.error("Cannot write pf rules tempfile: %s", err)
            return False

        cmd = ["pfctl", "-a", self._PF_ANCHOR, "-f", tmp_path]
        ok = self._run_action(cmd, description)
        if ok:
            self._run_action(["pfctl", "-E"], "enable pf")
        return ok

    def _read_pf_anchor(self) -> str:
        try:
            completed = subprocess.run(
                ["pfctl", "-a", self._PF_ANCHOR, "-s", "rules"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            return completed.stdout or ""
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def _get_blocked_ports_macos(self) -> list[BlockedPort]:
        if not shutil.which("pfctl"):
            return []
        try:
            completed = subprocess.run(
                ["pfctl", "-a", self._PF_ANCHOR, "-s", "rules"],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as err:
            self.logger.warning("pfctl rule enumeration failed: %s", err)
            return []

        stderr = (completed.stderr or "").lower()
        if "permission denied" in stderr or "operation not permitted" in stderr:
            self.logger.error("pfctl requires root privileges to list anchor rules")
            return []

        blocked: list[BlockedPort] = []
        rule_pattern = re.compile(
            r"block\s+in\s+quick\s+proto\s+(tcp|udp).*?port\s+(?:=\s*)?(\d+)",
            re.IGNORECASE,
        )
        for line in (completed.stdout or "").splitlines():
            match = rule_pattern.search(line)
            if match:
                protocol = match.group(1).upper()
                port = int(match.group(2))
                blocked.append(BlockedPort(
                    port=port, protocol=protocol,
                    rule_name=f"{self._PF_ANCHOR}/{port}",
                ))
        return blocked

    def _run_action(self, cmd: list[str], description: str) -> bool:
        self.logger.info("Executing firewall action: %s | cmd=%s", description, cmd)
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15, check=False
            )
        except FileNotFoundError as err:
            self.logger.error("Command missing for %s: %s", description, err)
            return False
        except subprocess.TimeoutExpired as err:
            self.logger.error("Timeout while running %s: %s", description, err)
            return False

        ok = completed.returncode == 0
        log = self.logger.info if ok else self.logger.error
        log("Firewall action '%s' returncode=%s stdout=%s stderr=%s",
            description, completed.returncode,
            (completed.stdout or "").strip(), (completed.stderr or "").strip())
        return ok
