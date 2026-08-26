import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]

FORBIDDEN_INFRASTRUCTURE_SHA256 = {
    "0f23977528b5e7f5790f4cb648147edf8b51f23d84d47ca04ec5abf1540ff5c6",
    "cf24c47403cadc154a62549e7b6c2d15094325bccd5265c954e26be6ad1016be",
    "158b049aa7d77f915014ac17750db1b7c42e901766b50f3cecd82fd6d3d46008",
    "8401bb83c11dbdc393bd8c88acfe1f11831652b5939cb5a0a558a25223c0402b",
    "ca0d5b97ca08bc290a17485b1847ca52f77a6ee6f92381945bea021a5a6e18f7",
    "7c5126911452228d18a392ba92965806faa64d86b92ed4c13e9267db332dcf03",
    "59d6be025c85e31ffcbe353fd281f981a31c65c7f3915d3e4ba914d1d7fab244",
}
INFRASTRUCTURE_VALUE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+|(?:\d{1,3}\.){3}\d{1,3})(?![\w.-])",
    re.IGNORECASE,
)


def test_runtime_sources_contain_no_production_infrastructure() -> None:
    paths = [
        ROOT / "cloudbrowser" / "app.py",
        ROOT / "cloudbrowser" / "main.py",
        ROOT / "native-client" / "macos" / "Sources" / "IdenGridApp" / "IdenGridApp.swift",
        ROOT / "windows-client" / "src" / "IdenGrid.Windows.Wpf" / "MainWindow.xaml.cs",
    ]
    text = "\n".join(path.read_text() for path in paths)
    candidate_hashes = {
        hashlib.sha256(value.lower().encode()).hexdigest()
        for value in INFRASTRUCTURE_VALUE.findall(text)
    }
    assert candidate_hashes.isdisjoint(FORBIDDEN_INFRASTRUCTURE_SHA256)


def test_clients_require_bundled_configuration_without_production_fallback() -> None:
    mac = (ROOT / "native-client" / "macos" / "Sources" / "IdenGridApp" / "IdenGridApp.swift").read_text()
    windows = (ROOT / "windows-client" / "src" / "IdenGrid.Windows.Wpf" / "MainWindow.xaml.cs").read_text()
    assert "ClientConfiguration" in mac
    assert "ClientConfiguration" in windows
    assert "IDENGRID_API_BASE_URL" not in mac
    assert "IDENGRID_API_BASE_URL" not in windows


def test_control_plane_has_no_automatic_production_topology_seed() -> None:
    app = (ROOT / "cloudbrowser" / "app.py").read_text()
    assert "pilot_nodes" not in app
    assert "pilot_topology_seeded_v1" not in app
