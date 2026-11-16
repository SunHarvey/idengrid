"""Fixture-only exercise of the real PowerShell assembly entrypoint, not a release artifact.

The real browser provenance validator and dotnet publish are replaced in a private
sandbox; the build script itself is copied byte-for-byte and executed by pwsh.
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(os.environ.get('ASSEMBLY_BASELINE_SCRIPT', ROOT / 'Build-IdenGrid-Windows.ps1'))
PWSH = os.environ.get('IDENGRID_PWSH') or shutil.which('pwsh')


def pe(machine=0x8664):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x96, 0x0002)
    struct.pack_into("<H", data, 0x98, 0x20B)
    return bytes(data)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(case):
    if not PWSH:
        raise RuntimeError('Set IDENGRID_PWSH or make pwsh available on PATH')
    with tempfile.TemporaryDirectory(prefix="idengrid-assembly-fixture-", dir=os.environ.get('IDENGRID_TEST_TEMP_DIR')) as sandbox:
        root = Path(sandbox)
        shutil.copyfile(SCRIPT, root / 'Build-IdenGrid-Windows.ps1')
        (root / "Test-IdenGridBrowserRuntimeManifest.ps1").write_text('''param($BrowserRuntimePath,$BrowserRuntimeManifestPath,$ExpectedRuntimeManifestSha256,$BrowserRuntimeArchivePath,$MediaGateResultPath)
$ErrorActionPreference = 'Stop'
# NON-PRODUCTION STUB. Never claim this tested Brave provenance or media.
if ($env:FIXTURE_REJECT_BROWSER -eq '1') { throw 'fixture browser/media provenance gate rejected input' }
$runtime = [IO.Path]::GetFullPath($BrowserRuntimePath)
if ($runtime -like '*.staging-*/Components/Browser' -and $env:FIXTURE_MUTATE_AGENT -eq '1') {
    [IO.File]::AppendAllText((Join-Path (Split-Path $runtime -Parent) 'idengrid-agent.exe'), 'changed')
}
[pscustomobject]@{ RuntimePath = $runtime; ManifestPath = [IO.Path]::GetFullPath($BrowserRuntimeManifestPath); RuntimeExecutableSha256 = (Get-FileHash (Join-Path $runtime 'brave.exe') -Algorithm SHA256).Hash.ToLowerInvariant(); ManifestSha256 = (Get-FileHash $BrowserRuntimeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() }
''')
        stub = root / "bin" / ("dotnet.cmd" if os.name == "nt" else "dotnet")
        stub.parent.mkdir()
        if os.name == "nt":
            stub.write_text('@echo off\r\nREM NON-PRODUCTION publish stub\r\n:again\r\nif "%~1"=="" exit /b 2\r\nif "%~1"=="-o" (\r\n shift\r\n mkdir "%~1"\r\n > "%~1\\publish-marker" echo fixture only\r\n if "%FIXTURE_FORBIDDEN%"=="1" ( > "%~1\\Cookies" echo fixture )\r\n exit /b 0\r\n)\r\nshift\r\ngoto again\r\n')
        else:
            stub.write_text('#!/bin/sh\n# NON-PRODUCTION publish stub: writes marker and no WPF binary\nwhile [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then shift; mkdir -p "$1"; printf "fixture only" > "$1/publish-marker"; if [ "$FIXTURE_FORBIDDEN" = "1" ]; then printf fixture > "$1/Cookies"; fi; exit 0; fi; shift; done\nexit 2\n')
            stub.chmod(0o755)
        browser = root / 'browser'
        browser.mkdir()
        (browser / 'brave.exe').write_bytes(b'fixture browser')
        manifest = root / 'manifest.json'
        manifest.write_text('{}')
        archive = root / 'browser.zip'
        archive.write_bytes(b'fixture')
        media = root / 'media.json'
        media.write_text('{}')
        output = root / 'previous'
        output.mkdir()
        (output / 'old-output').write_text('preserve')
        agent = root / 'agent.exe'
        contents = pe(0x14c) if case == 'x86' else pe()
        if case == 'empty': contents = b''
        if case == 'nonpe': contents = b'ELF' + b'\0' * 509
        agent.write_bytes(contents)
        if case == 'missing': agent.unlink()
        args = [PWSH, '-NoProfile', '-NonInteractive', '-File', str(root / 'Build-IdenGrid-Windows.ps1'),
                '-ApiBaseUrl', 'https://example.invalid', '-BrowserRuntimePath', str(browser),
                '-BrowserRuntimeManifestPath', str(manifest), '-ExpectedRuntimeManifestSha256', sha(manifest.read_bytes()),
                '-BrowserRuntimeArchivePath', str(archive), '-MediaGateResultPath', str(media)]
        if not os.environ.get('ASSEMBLY_BASELINE_SCRIPT'):
            args += ['-AgentPath', str(agent), '-ExpectedAgentSha256', ('0' * 64 if case == 'bad-hash' else sha(contents))]
        args += ['-OutputDirectory', str(output)]
        env = dict(os.environ, PATH=str(stub.parent) + os.pathsep + os.environ['PATH'],
                   FIXTURE_MUTATE_AGENT='1' if case == 'mutated' else '0',
                   FIXTURE_REJECT_BROWSER='1' if case == 'browser-gate' else '0',
                   FIXTURE_FORBIDDEN='1' if case == 'forbidden' else '0')
        print('COMMAND:', ' '.join(args), flush=True)
        result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=25, check=False)
        print('POWERSHELL EXIT:', result.returncode, '\nSTDOUT:', result.stdout, '\nSTDERR:', result.stderr, flush=True)
        target = output / 'Components' / 'idengrid-agent.exe'
        if case == 'success':
            assert result.returncode == 0, 'valid PE fixture rejected'
            assert target.read_bytes() == contents, 'copied Agent differs from fixture'
            assert (output / 'publish-marker').exists(), 'publish stub did not execute'
            assert not (output / 'old-output').exists(), 'old output was not promoted'
        else:
            assert result.returncode != 0, f'{case} unexpectedly accepted'
            if not os.environ.get('ASSEMBLY_BASELINE_SCRIPT'):
                reason = {
                    'missing': 'does not exist',
                    'empty': 'empty or too short',
                    'bad-hash': 'does not match ExpectedAgentSha256',
                    'x86': 'must target Windows x64',
                    'nonpe': 'not a Windows PE image',
                    'mutated': 'does not match ExpectedAgentSha256',
                    'browser-gate': 'fixture browser/media provenance gate rejected input',
                    'forbidden': 'Portable output contains forbidden private or diagnostic artifacts',
                }[case]
                assert reason in result.stderr, f'{case} failed for an unrelated reason: {result.stderr}'
            assert (output / 'old-output').read_text() == 'preserve', 'old output destroyed'
            assert not target.exists(), 'failed output promoted'
        print('PASS:', case, '(assembly behavior only; browser/media/real WPF NOT validated)')


if __name__ == '__main__':
    run(sys.argv[1])
