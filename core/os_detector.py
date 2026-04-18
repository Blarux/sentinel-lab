import ctypes
import os
import platform
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class OSInfo:
    family: str
    release: str
    version: str
    machine: str

    @property
    def is_windows(self) -> bool:
        return self.family == "windows"

    @property
    def is_linux(self) -> bool:
        return self.family == "linux"


def detect_os() -> OSInfo:
    system = platform.system().lower()
    if system not in {"windows", "linux"}:
        raise RuntimeError(
            f"Unsupported OS: {platform.system()}. Sentinel-Lab supports Windows and Linux."
        )
    return OSInfo(
        family=system,
        release=platform.release(),
        version=platform.version(),
        machine=platform.machine(),
    )


def is_admin() -> bool:
    try:
        if platform.system().lower() == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def require_admin(console=None) -> None:
    if is_admin():
        return

    msg = (
        "Sentinel-Lab requires elevated privileges.\n"
        "  - Windows: run the terminal as Administrator.\n"
        "  - Linux:   run with sudo."
    )
    if console is not None:
        console.print(f"[bold red]ACCESS DENIED[/bold red]\n{msg}")
    else:
        print(msg, file=sys.stderr)
    sys.exit(2)
