import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "src" / "IdenGrid.Windows.Wpf"


def text(name: str) -> str:
    return (PROJECT / name).read_text(encoding="utf-8")


def test_wpf_project_is_self_contained_windows_x64_without_winui():
    project = text("IdenGrid.Windows.Wpf.csproj")
    assert "<UseWPF>true</UseWPF>" in project
    assert "<TargetFramework>net10.0-windows</TargetFramework>" in project
    assert "<RuntimeIdentifier>win-x64</RuntimeIdentifier>" in project
    assert "<SelfContained>true</SelfContained>" in project
    assert "Microsoft.WindowsAppSDK" not in project
    assert 'PackageReference Include="System.Drawing.Common"' not in project
    assert 'PackageReference Include="System.Security.Cryptography.ProtectedData"' not in project


def test_api_origin_is_loaded_from_embedded_https_configuration():
    code = text("ClientConfiguration.cs")
    project = text("IdenGrid.Windows.Wpf.csproj")
    main = text("MainWindow.xaml.cs")
    assert "IdenGrid.ClientConfig.json" in code and project
    assert "https://api.example.com" not in main
    assert "IDENGRID_API_BASE_URL" not in main
    assert "ClientConfiguration.LoadApiBaseAddress()" in main
    assert "UriSchemeHttps" in code


def test_release_build_requires_explicit_api_origin_and_generates_embedded_config():
    script = (ROOT / "Build-IdenGrid-Windows.ps1").read_text()
    assert "IDENGRID_API_BASE_URL" in script
    assert "https" in script.lower()
    assert "client-config.json" in script
    assert "dotnet publish" in script
    assert "api.example.com" not in script


def test_login_and_workspace_surfaces_exist():
    view = text("MainWindow.xaml")
    for marker in (
        'x:Name="LoginPanel"',
        'x:Name="UsernameBox"',
        'x:Name="PasswordBox"',
        'Click="LoginClick"',
        'x:Name="StorePanel"',
        'x:Name="SearchBox"',
        'x:Name="StoreList"',
        'Click="RefreshClick"',
        'Click="LogoutClick"',
        'Click="ExitApplication"',
    ):
        assert marker in view


def test_login_uses_native_api_and_clears_password():
    code = text("MainWindow.xaml.cs")
    assert "NativeApiClient" in code
    assert "LoginAsync(" in code
    assert "GetStoresAsync(" in code
    assert "PasswordBox.Clear()" in code
    assert "LoginPresentation.FailureMessage" in code
    assert "StoreFilter.Apply" in code


def test_launch_script_targets_wpf_release():
    script = text("Run-IdenGrid-Windows-Dev.cmd")
    assert "IdenGrid.Windows.exe" in script
    assert "artifacts\\IdenGrid.Windows.Dev" in script


def test_store_actions_match_macos_and_are_real_event_entrypoints():
    view = text("MainWindow.xaml")
    assert 'Click="StorePrimaryClick"' in view
    assert 'Click="StoreCloseClick"' in view
    assert 'Click="QuitAllClick"' in view
    assert 'IsEnabled="False"' not in view
    assert "退出全部" in view
    assert "{Binding LaunchButtonText}" in view
    assert "{Binding StateLine}" in view


def test_windows_process_manager_is_fail_closed():
    code = text("WindowsStoreProcessManager.cs")
    assert "RedirectStandardInput = true" in code
    assert "NamedPipeClientStream" in code
    assert 'socks5://' in code
    assert "api.ipify.org" in code
    assert "--proxy-server=" in code
    assert "--proxy-bypass-list=<-loopback>" in code
    assert "--disable-quic" in code
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in code
    assert "WindowsProfileLayout.UserDataDirectory" in code


def test_windows_icons_and_store_taskbar_identity_are_explicit():
    project = text("IdenGrid.Windows.Wpf.csproj")
    manager = text("WindowsStoreProcessManager.cs")
    icon = text("StoreTaskbarIcon.cs")
    assert "<ApplicationIcon>Assets\\idengrid.ico</ApplicationIcon>" in project
    assert "CopyToOutputDirectory" in project
    assert "WM_SETICON" in manager
    assert "SetWindowText" in manager
    assert "MaintainBrowserIdentityAsync" in manager
    assert "· IdenGrid" in manager
    assert "StoreTaskbarIcon.Create" in manager
    assert "string LabelFor" in icon
    assert "EnumerateRunes" in icon
    assert "Take(2)" in icon
    assert "store-taskbar.ico" in icon
    assert "using System.Drawing;" in icon
    assert "LoadStoreIcon(iconPath)" in manager


def test_store_taskbar_identity_prioritizes_large_store_character():
    icon = text("StoreTaskbarIcon.cs")
    assert "BrandMarkScale = 0.28f" in icon
    assert "SingleCharacterFontScale = 0.64f" in icon
    assert "TwoCharacterFontScale = 0.46f" in icon
    assert "FillRoundedRectangle" in icon
    assert "ReadableTextColor" in icon
    assert 'Contains("香港"' not in icon
    assert 'Contains("新加坡"' not in icon


def test_egress_probe_never_opens_as_a_browser_tab():
    manager = text("WindowsStoreProcessManager.cs")
    assert manager.count('https://api.ipify.org') == 1
    assert 'ArgumentList.Add("https://api.ipify.org")' not in manager
    assert 'ArgumentList.Add("--new-window")' not in manager


def test_windows_session_uses_dpapi_and_never_persists_password():
    vault = text("WindowsSessionVault.cs")
    assert "ProtectedData.Protect" in vault
    assert "ProtectedData.Unprotect" in vault
    assert "DataProtectionScope.CurrentUser" in vault
    assert "RefreshToken" in vault
    assert "AccessToken" not in vault
    assert "Password" not in vault


def test_token_refresh_rotates_vault_and_hot_updates_agents():
    window = text("MainWindow.xaml.cs")
    manager = text("WindowsStoreProcessManager.cs")
    assert "RestoreSessionAsync" in window
    assert "RefreshAsync(" in window
    assert "AccessTokenRefreshSchedule.Delay" in window
    assert "_sessionVault.Save" in window
    assert "UpdateAccessTokenAsync" in window
    assert '"update_token"' in manager
    assert "native_access_token" in manager
    assert "QuitAllAsync" in window


def test_password_visibility_matches_macos_behavior():
    view = text("MainWindow.xaml")
    code = text("MainWindow.xaml.cs")
    assert 'x:Name="VisiblePasswordBox"' in view
    assert 'x:Name="PasswordVisibilityButton"' in view
    assert 'Click="TogglePasswordVisibility"' in view
    assert 'AutomationProperties.Name="显示密码"' in view
    assert 'IsDefault="True"' in view
    assert "TogglePasswordVisibility" in code
    assert "VisiblePasswordBox.Text" in code
    assert "PasswordBox.Clear()" in code
    assert "VisiblePasswordBox.Clear()" in code


def test_each_store_gets_privacy_extension_without_secrets():
    project = text("IdenGrid.Windows.Wpf.csproj")
    manager = text("WindowsStoreProcessManager.cs")
    privacy = text("Components/Extension/privacy.js")
    manifest = text("Components/Extension/manifest.json")
    assert "Components\\Extension\\**\\*" in project
    assert "PrepareStoreExtension" in manager
    assert "identity.json" in manager
    assert "--load-extension=" in manager
    assert "--disable-extensions-except=" in manager
    assert 'webRTCIPHandlingPolicy: "disable_non_proxied_udp"' in privacy
    assert '"permissions": ["privacy"]' in manifest
    assert "native_access_token" not in privacy
    assert "native_access_token" not in manifest


def test_store_identity_extension_preserves_original_webpage_titles():
    manifest = text("Components/Extension/manifest.json")
    content = text("Components/Extension/content.js")
    assert "title-prefix.js" not in manifest
    assert "content.js" not in manifest
    assert "document.title" not in content


def test_store_latency_separates_central_reference_from_local_edge_rtt():
    view = text("MainWindow.xaml")
    window = text("MainWindow.xaml.cs")
    manager = text("WindowsStoreProcessManager.cs")
    assert "中央节点参考" in window
    assert "本机到实际Edge" in window
    assert "{Binding LocalLatencyLine}" in view
    assert "PollEdgeLatencyAsync" in manager
    assert "edge_latency" in manager
    assert "ewma_rtt_ms" in manager


def test_release_build_requires_a_pinned_media_runtime_and_copies_its_manifest():
    script = (ROOT / "Build-IdenGrid-Windows.ps1").read_text(encoding="utf-8")
    assert "BrowserRuntimePath" in script
    assert "BrowserRuntimeManifestPath" in script
    assert "ExpectedRuntimeManifestSha256" in script
    assert "Test-IdenGridBrowserRuntimeManifest.ps1" in script
    validator_call = script.split("& $runtimeValidator", 1)[1].split("New-Item", 1)[0]
    assert "-ExpectedRuntimeManifestSha256 $ExpectedRuntimeManifestSha256" in validator_call
    assert "Components\\Browser" in script
    assert "idengrid-runtime-manifest.json" in script
    assert "Copy-Item" in script
    validator_calls = [match.start() for match in re.finditer(r"& \$runtimeValidator", script)]
    assert len(validator_calls) == 2
    runtime_copy = script.index("Copy-Item -LiteralPath $_.FullName")
    manifest_copy = script.index("Copy-Item -LiteralPath $browserRuntime.ManifestPath")
    assert runtime_copy < validator_calls[1] < manifest_copy
    packaged_validator_call = script[validator_calls[1]:manifest_copy]
    assert "-BrowserRuntimePath $browserDestination" in packaged_validator_call
    assert "-ExpectedRuntimeManifestSha256 $ExpectedRuntimeManifestSha256" in packaged_validator_call


def test_release_build_is_transactional_and_rejects_private_runtime_artifacts():
    script = (ROOT / "Build-IdenGrid-Windows.ps1").read_text(encoding="utf-8")
    publish = script.split("dotnet publish", 1)[1]
    assert "$LASTEXITCODE" in publish
    assert "staging-" in script
    assert "backup-" in script
    assert "Move-Item" in script
    assert "OutputDirectory" in script
    for forbidden in ("Cookies", "Login Data", "Local State", "*.log", "*.dmp", "*.pma"):
        assert forbidden in script
    # Promotion must happen only after the staged tree has been scanned.
    assert script.index("forbiddenPatterns") < script.rindex("Move-Item")


def test_media_runtime_manifest_verifies_archive_executable_identity_and_external_gate():
    validator = (ROOT / "Test-IdenGridBrowserRuntimeManifest.ps1").read_text(encoding="utf-8")
    for field in (
        "runtime_id",
        "source_revision",
        "archive_sha256",
        "distribution_review_reference",
        "browser_executable",
        "browser_executable_sha256",
    ):
        assert field in validator
    assert "BrowserRuntimeArchivePath" in validator
    assert "MediaGateResultPath" in validator
    assert "function Get-NormalizedSha256" in validator
    assert validator.count("Get-NormalizedSha256") >= 4
    assert "Get-AuthenticodeSignature" in validator
    assert "Brave Software, Inc." in validator
    assert "OriginalFilename" in validator
    assert "ProductName" in validator
    assert '"brave.exe"' in validator
    assert "runtime_manifest_sha256" in validator
    assert "active_session" in validator
    assert "decoded_aac_bytes" in validator
    assert 'manifest.media_gate' not in validator
    assert "RuntimeExecutable" in validator
    assert "GetFileName" in validator


def test_runtime_manifest_trust_anchor_is_checked_before_manifest_is_parsed():
    validator = (ROOT / "Test-IdenGridBrowserRuntimeManifest.ps1").read_text(encoding="utf-8")
    assert "ExpectedRuntimeManifestSha256" in validator
    assert "ExpectedRuntimeManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$'" in validator
    hash_check = validator.index("does not match ExpectedRuntimeManifestSha256")
    manifest_parse = validator.index("ConvertFrom-Json")
    assert hash_check < manifest_parse


def test_runtime_manifest_inventory_is_canonical_complete_and_content_bound():
    validator = (ROOT / "Test-IdenGridBrowserRuntimeManifest.ps1").read_text(encoding="utf-8")
    assert "runtime_files" in validator
    assert "IsPathRooted" in validator
    assert "OrdinalIgnoreCase" in validator
    assert "GetInvalidFileNameChars" in validator
    assert 'EndsWith(".")' in validator
    assert "CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]" in validator
    assert "Get-ChildItem -LiteralPath $runtime -File -Recurse -Force" in validator
    assert ".Length" in validator
    assert "Get-NormalizedSha256" in validator
    assert 'Equals("idengrid-runtime-manifest.json", [StringComparison]::OrdinalIgnoreCase)' in validator
    assert "Browser runtime manifest must remain outside" in validator
    for failure in (
        "invalid relative path",
        "duplicate path",
        "file set does not match",
        "size does not match",
        "SHA-256 does not match",
    ):
        assert failure in validator


def test_browser_runtime_is_selected_from_manifest_without_executable_renaming():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert "idengrid-runtime-manifest.json" in manager
    assert "browser_executable" in manager
    assert "ResolveBrowserExecutable" in manager


def test_browser_runtime_manifest_parser_accepts_utf8_bom():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert "JsonDocument.Parse(File.ReadAllText(manifestPath))" in manager
    assert "JsonDocument.Parse(File.ReadAllBytes(manifestPath))" not in manager


def test_download_directory_is_persisted_in_each_store_profile():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert "ConfigureBrowserProfile" in manager
    assert 'preferences["download"]' in manager
    assert 'preferences["savefile"]' in manager
    assert "--downloads-path" not in manager


def test_each_store_restores_its_previous_browser_session():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert 'session["restore_on_startup"] = 1' in manager
    assert 'preferences["session"] = session' in manager
    assert 'start.ArgumentList.Add("--restore-last-session")' in manager


def test_brave_product_analytics_is_disabled_without_an_informer():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert "ConfigureBrowserLocalState(profile)" in manager
    assert 'p3a["enabled"] = false' in manager
    assert 'p3a["notice_acknowledged"] = true' in manager


def test_brave_crash_reporting_is_disabled_without_a_permission_prompt():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert 'brave["dont_ask_for_crash_reporting"] = true' in manager
    assert 'metrics["reporting_enabled"] = false' in manager
    assert 'localState["user_experience_metrics"] = metrics' in manager


def test_fail_closed_gives_brave_a_graceful_session_flush_before_forced_termination():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    unexpected_exit = manager.split("private async void HandleUnexpectedExit", 1)[1].split(
        "private void SetState", 1
    )[0]
    assert "await StopBrowserAsync(record.Browser)" in unexpected_exit
    assert "StopProcessAsync(record.Browser" not in unexpected_exit


def test_launch_and_shutdown_cleanup_survives_browser_stop_failures():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    launch_failure = manager.split("catch (Exception error)", 1)[1].split(
        "public async Task CloseAsync", 1
    )[0]
    close = manager.split("public async Task CloseAsync", 1)[1].split(
        "public async Task QuitAllAsync", 1
    )[0]
    unexpected = manager.split("private async void HandleUnexpectedExit", 1)[1].split(
        "private void SetState", 1
    )[0]
    assert "StopBrowserAsync(record.Browser)" in launch_failure
    assert "finally" in launch_failure
    assert "finally" in close
    assert "CleanupRecord" in close
    assert "try" in unexpected and "catch" in unexpected and "finally" in unexpected
    assert "CleanupRecord" in unexpected


def test_process_exit_handlers_are_armed_without_a_registration_race():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    launch = manager.split("var runningRecord = new RunningStore", 1)[1].split(
        "catch (Exception error)", 1
    )[0]
    assert launch.index("agent.Exited +=") < launch.index("agent.EnableRaisingEvents = true")
    assert launch.index("browser.Exited +=") < launch.index("browser.EnableRaisingEvents = true")
    assert launch.index("_running.TryAdd(store.Id, runningRecord)") < launch.index(
        "agent.EnableRaisingEvents = true"
    )
    assert launch.index("browser.EnableRaisingEvents = true") < launch.index("agent.HasExited")
    assert launch.index("browser.EnableRaisingEvents = true") < launch.index("browser.HasExited")


def test_launch_failure_claims_the_record_before_process_cleanup():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    launch_failure = manager.split("catch (Exception error)", 1)[1].split(
        "public async Task CloseAsync", 1
    )[0]
    claim = launch_failure.index("TryClaimCleanup(record)")
    assert claim < launch_failure.index("StopBrowserAsync(record.Browser)")
    assert claim < launch_failure.index("StopProcessAsync(record.Agent")
    assert "record.Agent.EnableRaisingEvents = false" in launch_failure
    assert "record.Browser.EnableRaisingEvents = false" in launch_failure


def test_store_runtime_maps_are_safe_for_ui_poll_and_exit_threads():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    for field in ("_running", "_states", "_edgeLatencies"):
        assert re.search(
            rf"ConcurrentDictionary<string, [^>]+>\s+{field}\s*=",
            manager,
        )


def test_each_running_store_has_one_atomic_cleanup_owner():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    running_store = manager.split("private sealed", 1)[1]
    assert "Interlocked.CompareExchange" in running_store
    assert "CleanupCompletion" in running_store

    launch_failure = manager.split("catch (Exception error)", 1)[1].split(
        "public async Task CloseAsync", 1
    )[0]
    close = manager.split("public async Task CloseAsync", 1)[1].split(
        "public async Task QuitAllAsync", 1
    )[0]
    unexpected = manager.split("private async void HandleUnexpectedExit", 1)[1].split(
        "private void CleanupRecord", 1
    )[0]
    assert "TryClaimCleanup(record)" in launch_failure
    assert "TryClaimCleanup(record)" in close
    assert "TryClaimCleanup(record)" in unexpected


def test_launch_only_succeeds_for_its_live_registered_record():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    existing = manager.split("while (_running.TryGetValue(store.Id, out var existing))", 1)[1].split(
        "var storeRoot", 1
    )[0]
    assert "lock (existing.LifecycleGate)" in existing
    assert "!existing.CleanupClaimed" in existing
    assert "!existing.Agent.HasExited" in existing
    assert "!existing.Browser.HasExited" in existing
    assert "await existing.CleanupCompletion.Task" in existing

    launch = manager.split("var runningRecord = new RunningStore", 1)[1].split(
        "catch (Exception error)", 1
    )[0]
    assert "ReferenceEquals(registered, runningRecord)" in launch
    assert "runningRecord.CleanupClaimed" in launch
    assert "agent.HasExited" in launch
    assert "browser.HasExited" in launch
    assert "HandleUnexpectedExit(runningRecord," in launch


def test_store_startup_is_registered_before_side_effects_and_shared_by_launchers():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    launch = manager.split("public async Task LaunchAsync", 1)[1].split(
        "public async Task CloseAsync", 1
    )[0]
    assert "ConcurrentDictionary<string, StartingStore> _starting" in manager
    assert launch.index("_starting.GetOrAdd(store.Id, candidateStartup)") < launch.index(
        "Directory.CreateDirectory"
    )
    assert "await startup.Completion.Task.WaitAsync(cancellationToken)" in launch
    assert "ReferenceEquals(registered, startedRecord)" in launch
    assert "throw new InvalidOperationException" in launch
    assert "CreateLinkedTokenSource(cancellationToken)" in manager
    assert "startup.Cancellation.Token.ThrowIfCancellationRequested()" in launch
    assert "new KeyValuePair<string, StartingStore>(store.Id, startup)" in launch
    assert "startup.Completion.TrySetResult()" in launch


def test_shutdown_cancels_startup_waits_for_it_and_rechecks_running_record():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    close = manager.split("public async Task CloseAsync", 1)[1].split(
        "public async Task QuitAllAsync", 1
    )[0]
    assert "startup.Cancellation.Cancel()" in close
    assert "await startup.Completion.Task" in close
    assert close.index("await startup.Completion.Task") < close.rindex(
        "_running.TryGetValue(storeId, out var record)"
    )

    quit_all = manager.split("public async Task QuitAllAsync", 1)[1].split(
        "public async Task UpdateAccessTokenAsync", 1
    )[0]
    assert "_starting.Keys" in quit_all
    assert "_running.Keys" in quit_all
    assert "Union" in quit_all
    assert "await _launchRegistrationGate.WaitAsync()" in quit_all
    assert "Interlocked.Increment(ref _drainGeneration)" in quit_all
    assert "Volatile.Write(ref _drainingLaunches, 1)" in quit_all
    assert "Volatile.Write(ref _drainingLaunches, 0)" in quit_all
    assert "_launchRegistrationGate.Release()" in quit_all

    launch = manager.split("public async Task LaunchAsync", 1)[1].split(
        "private async Task LaunchOwnedAsync", 1
    )[0]
    assert "observedDrainGeneration" in launch
    assert "await _launchRegistrationGate.WaitAsync(cancellationToken)" in launch
    assert "Volatile.Read(ref _drainingLaunches)" in launch
    assert "Volatile.Read(ref _drainGeneration) != observedDrainGeneration" in launch
    assert launch.index("_launchRegistrationGate.WaitAsync") < launch.index(
        "_starting.GetOrAdd(store.Id, candidateStartup)"
    )


def test_edge_latency_publication_is_guarded_against_stale_records():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    poll = manager.split("private async Task PollEdgeLatencyAsync", 1)[1].split(
        "private async void HandleUnexpectedExit", 1
    )[0]
    assert "PublishEdgeLatency(record" in poll

    publish = manager.split("private bool PublishEdgeLatency", 1)[1].split(
        "private async void HandleUnexpectedExit", 1
    )[0]
    assert "lock (record.LifecycleGate)" in publish
    assert "record.CleanupClaimed" in publish
    assert "_running.TryGetValue(record.StoreId, out var registered)" in publish
    assert "ReferenceEquals(registered, record)" in publish
    assert publish.index("ReferenceEquals(registered, record)") < publish.index(
        "_edgeLatencies[record.StoreId] = latency"
    )
    assert publish.index("ReferenceEquals(registered, record)") < publish.index(
        "StateChanged?.Invoke(record.StoreId)"
    )
    locked_publish = publish.split("lock (record.LifecycleGate)", 1)[1].split(
        "        }\n        StateChanged?.Invoke(record.StoreId)", 1
    )[0]
    assert "StateChanged?.Invoke" not in locked_publish


def test_lifecycle_lock_never_invokes_synchronous_ui_callbacks():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    lock_bodies = []
    cursor = 0
    marker = "lock ("
    while True:
        lock_at = manager.find(marker, cursor)
        if lock_at < 0:
            break
        brace_at = manager.find("{", lock_at)
        depth = 0
        for index in range(brace_at, len(manager)):
            if manager[index] == "{":
                depth += 1
            elif manager[index] == "}":
                depth -= 1
                if depth == 0:
                    lock_bodies.append(manager[brace_at + 1 : index])
                    cursor = index + 1
                    break
        else:
            raise AssertionError("unterminated lock body")

    lifecycle_bodies = lock_bodies
    assert len(lifecycle_bodies) >= 4
    for body in lifecycle_bodies:
        assert "StateChanged?.Invoke" not in body
        assert "Activate(" not in body
        assert "ShowWindow(" not in body
        assert "SetForegroundWindow(" not in body

    launch_lock = next(
        body for body in lifecycle_bodies if "StoreRuntimeState.Running" in body
    )
    assert "SetState(" not in launch_lock
    assert '_states[store.Id] = StoreRuntimeState.Running' in launch_lock


def test_windows_build_docs_show_every_required_provenance_argument():
    for readme_name in ("README.md", "README_EN.md"):
        readme = (ROOT.parent / readme_name).read_text(encoding="utf-8")
        example = readme.split("Build-IdenGrid-Windows.ps1", 1)[1].split("```", 1)[0]
        for argument in (
            "-BrowserRuntimePath",
            "-BrowserRuntimeManifestPath",
            "-ExpectedRuntimeManifestSha256",
            "-BrowserRuntimeArchivePath",
            "-MediaGateResultPath",
        ):
            assert argument in example


def test_browser_shutdown_closes_every_visible_top_level_window_for_the_root_process():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    shutdown = manager.split("private static async Task StopBrowserAsync", 1)[1].split(
        "private static async Task StopProcessAsync", 1
    )[0]
    assert "CloseBrowserWindows(process)" in shutdown
    assert "EnumWindows" in manager
    assert "GetWindowThreadProcessId" in manager
    assert "IsWindowVisible" in manager
    assert "PostMessage" in manager
    assert "WM_CLOSE" in manager


def test_managed_store_shutdown_does_not_prompt_to_confirm_closing_multiple_tabs():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert 'brave["enable_window_closing_confirm"] = false' in manager
    assert 'preferences["brave"] = brave' in manager


def test_brave_does_not_remain_in_background_after_its_store_window_closes():
    manager = (PROJECT / "WindowsStoreProcessManager.cs").read_text(encoding="utf-8")
    assert 'start.ArgumentList.Add("--disable-background-mode")' in manager
    assert 'backgroundMode["enabled"] = false' in manager
    assert 'backgroundMode["enabled_on_next_startup"] = false' in manager


def test_interactive_media_gate_requires_h264_aac_and_advancing_decoded_frames():
    gate = (ROOT / "Test-IdenGridBrowserMedia.ps1").read_text(encoding="utf-8")
    assert "BrowserRuntimeManifestPath" in gate
    assert "browser_executable" in gate
    assert "chrome.exe" not in gate
    assert 'video/mp4; codecs=\"avc1.42E01E\"' in gate
    assert 'audio/mp4; codecs=\"mp4a.40.2\"' in gate
    assert "currentTime" in gate
    assert "totalVideoFrames" in gate
    assert "webkitAudioDecodedByteCount" in gate
    assert "decoded_aac_bytes" in gate
    assert "WTSEnumerateSessions" in gate
    assert "WTSActive" in gate
    assert "WTSClientProtocolType" in gate
    assert "ResultPath" in gate
    assert "browser_executable_sha256" in gate
    assert "runtime_manifest_sha256" in gate
    assert "active_session" in gate
    assert "fixture" in gate
    assert "Interactive" in gate
    assert "--headless" not in gate
