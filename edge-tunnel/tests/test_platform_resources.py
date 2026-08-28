import importlib
from types import SimpleNamespace

from edge_tunnel import resources
from edge_tunnel.resources import (
    LinuxResourceProvider,
    WindowsResourceProvider,
    create_resource_provider,
)


def test_linux_resource_provider_preserves_proc_and_statvfs_contract():
    proc = {
        "/proc/loadavg": "0.42 0.20 0.10 1/100 99\n",
        "/proc/meminfo": "MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\n",
        "/proc/uptime": "12345.67 456.00\n",
    }

    class Vfs:
        f_frsize = 4096
        f_blocks = 25_000_000
        f_bavail = 20_000_000

    provider = LinuxResourceProvider(read_text=lambda path: proc[path], statvfs=lambda path: Vfs())

    assert provider() == {
        "load_1m": 0.42,
        "memory_total_bytes": 4_294_967_296,
        "memory_available_bytes": 3_221_225_472,
        "disk_total_bytes": 102_400_000_000,
        "disk_free_bytes": 81_920_000_000,
        "uptime_seconds": 12_345.67,
    }


def test_windows_resource_provider_reports_same_resource_contract():
    fake_psutil = SimpleNamespace(
        getloadavg=lambda: (1.25, 0.75, 0.5),
        virtual_memory=lambda: SimpleNamespace(total=16_000, available=6_000),
        disk_usage=lambda path: SimpleNamespace(total=50_000, free=20_000),
        boot_time=lambda: 1_000.0,
    )
    provider = WindowsResourceProvider(
        psutil_module=fake_psutil,
        system_drive="D:\\",
        clock=lambda: 4_600.5,
    )

    assert provider() == {
        "load_1m": 1.25,
        "memory_total_bytes": 16_000,
        "memory_available_bytes": 6_000,
        "disk_total_bytes": 50_000,
        "disk_free_bytes": 20_000,
        "uptime_seconds": 3_600.5,
    }


def test_resource_provider_factory_selects_linux():
    provider = create_resource_provider(system="Linux")

    assert isinstance(provider, LinuxResourceProvider)


def test_resource_provider_factory_selects_windows_with_injected_metrics():
    fake_psutil = SimpleNamespace()

    provider = create_resource_provider(system="Windows", psutil_module=fake_psutil)

    assert isinstance(provider, WindowsResourceProvider)
    assert provider._psutil is fake_psutil


def test_module_import_and_windows_factory_do_not_require_linux_statvfs(monkeypatch):
    try:
        with monkeypatch.context() as isolated:
            isolated.delattr(resources.os, "statvfs")
            reloaded = importlib.reload(resources)
            provider = reloaded.create_resource_provider(
                system="Windows", psutil_module=SimpleNamespace()
            )
            assert isinstance(provider, reloaded.WindowsResourceProvider)
    finally:
        importlib.reload(resources)


def test_resource_provider_factory_rejects_unsupported_platform():
    try:
        create_resource_provider(system="Plan9")
    except RuntimeError as exc:
        assert str(exc) == "unsupported resource platform: Plan9"
    else:
        raise AssertionError("unsupported platform was accepted")
