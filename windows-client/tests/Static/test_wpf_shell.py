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
    assert "System.Drawing" in project
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
