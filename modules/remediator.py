from __future__ import annotations

from dataclasses import dataclass

import psutil

from core import get_logger

from .firewall_manager import FirewallManager


@dataclass
class ActionResult:
    success: bool
    message: str


class Remediator:
    def __init__(self, firewall: FirewallManager | None = None) -> None:
        self.logger = get_logger("sentinel.remediator")
        self.firewall = firewall or FirewallManager()

    def kill_process(self, pid: int, force: bool = False, timeout: float = 5.0) -> ActionResult:
        if not pid or pid <= 0:
            return ActionResult(False, "Invalid PID.")
        if pid in (0, 1, 4):
            msg = f"Refusing to terminate protected system PID {pid}."
            self.logger.warning(msg)
            return ActionResult(False, msg)

        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            return ActionResult(False, f"PID {pid} not found.")
        except psutil.AccessDenied:
            return ActionResult(False, f"Access denied to PID {pid}.")

        try:
            if force:
                proc.kill()
            else:
                proc.terminate()
            proc.wait(timeout=timeout)
        except psutil.TimeoutExpired:
            self.logger.warning("Process %s (%s) did not exit in %ss; escalating to kill",
                                pid, name, timeout)
            try:
                proc.kill()
                proc.wait(timeout=timeout)
            except Exception as err:
                msg = f"Failed to kill PID {pid} ({name}): {err}"
                self.logger.error(msg)
                return ActionResult(False, msg)
        except (psutil.AccessDenied, psutil.NoSuchProcess) as err:
            return ActionResult(False, f"Could not stop PID {pid}: {err}")

        msg = f"Process {name} (PID {pid}) terminated."
        self.logger.info(msg)
        return ActionResult(True, msg)

    def close_port(self, port: int, protocol: str = "TCP") -> ActionResult:
        ok = self.firewall.block_port(port, protocol)
        if ok:
            msg = f"Firewall rule added to block {protocol.upper()}/{port}."
            self.logger.info(msg)
            return ActionResult(True, msg)
        msg = f"Failed to add block rule for {protocol.upper()}/{port}. See logs."
        return ActionResult(False, msg)

    def block_ip(self, ip: str) -> ActionResult:
        if not ip or ip in {"0.0.0.0", "127.0.0.1", "::1", "::"}:
            return ActionResult(False, f"Refusing to block reserved/local IP {ip}.")
        ok = self.firewall.block_ip(ip)
        if ok:
            msg = f"Firewall rule added to block IP {ip}."
            self.logger.info(msg)
            return ActionResult(True, msg)
        return ActionResult(False, f"Failed to block IP {ip}. See logs.")
