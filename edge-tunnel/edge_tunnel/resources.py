from __future__ import annotations

import importlib
import os
import platform
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol


class PsutilLike(Protocol):
    def getloadavg(self) -> tuple[float, float, float]: ...

    def virtual_memory(self) -> Any: ...

    def disk_usage(self, path: str) -> Any: ...

    def boot_time(self) -> float: ...


class LinuxResourceProvider:
    def __init__(
        self,
        *,
        read_text: Callable[[str], str] | None = None,
        statvfs: Callable[[str], Any] = os.statvfs,
    ) -> None:
        self._read_text = read_text or (lambda path: Path(path).read_text())
        self._statvfs = statvfs

    def __call__(self) -> dict[str, int | float]:
        memory = {}
        for line in self._read_text("/proc/meminfo").splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.split()[0]) * 1024
        filesystem = self._statvfs("/")
        return {
            "load_1m": float(self._read_text("/proc/loadavg").split()[0]),
            "memory_total_bytes": memory["MemTotal"],
            "memory_available_bytes": memory["MemAvailable"],
            "disk_total_bytes": filesystem.f_frsize * filesystem.f_blocks,
            "disk_free_bytes": filesystem.f_frsize * filesystem.f_bavail,
            "uptime_seconds": float(self._read_text("/proc/uptime").split()[0]),
        }


class WindowsResourceProvider:
    def __init__(
        self,
        *,
        psutil_module: PsutilLike,
        system_drive: str | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._psutil = psutil_module
        self._system_drive = system_drive or f"{os.environ.get('SystemDrive', 'C:')}\\"
        self._clock = clock

    def __call__(self) -> dict[str, int | float]:
        memory = self._psutil.virtual_memory()
        disk = self._psutil.disk_usage(self._system_drive)
        return {
            "load_1m": float(self._psutil.getloadavg()[0]),
            "memory_total_bytes": int(memory.total),
            "memory_available_bytes": int(memory.available),
            "disk_total_bytes": int(disk.total),
            "disk_free_bytes": int(disk.free),
            "uptime_seconds": float(self._clock() - self._psutil.boot_time()),
        }


def create_resource_provider(
    *,
    system: str | None = None,
    psutil_module: PsutilLike | None = None,
) -> LinuxResourceProvider | WindowsResourceProvider:
    selected = system or platform.system()
    if selected == "Linux":
        return LinuxResourceProvider()
    if selected == "Windows":
        metrics = psutil_module or importlib.import_module("psutil")
        return WindowsResourceProvider(psutil_module=metrics)
    raise RuntimeError(f"unsupported resource platform: {selected}")
