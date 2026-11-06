# 客户端构建与验收记录规范

使用本清单区分源码、开发构建、可运行便携包、签名/公证正式发布。每次验收都记录**日期、提交、目标 OS、产物绝对路径、完整 SHA-256、签名身份、实际执行结果和未测项**；不要复用上一版本的证据。示例配置只含保留测试值，真实值须经受保护渠道注入。

## 最小源码门禁

在仓库根目录运行（先按 README 安装对应平台依赖）：

```bash
uv sync --dev
uv run ruff check cloudbrowser scripts tests
uv run pytest -q
uv run pytest -q windows-client/tests/Static native-client/macos/Tests/Static
cd native-client/agent-rs
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Windows .NET Core 合同工程在具备 .NET 10 SDK 的环境另行运行：

```powershell
dotnet run --project .\windows-client\tests\IdenGrid.Core.ContractTests\IdenGrid.Core.ContractTests.csproj -c Release
```

静态/合同测试不证明桌面启动、运行时媒体、网络出口或系统级隔离。若依赖/SDK 不可用，要记录“未运行”，而不是写“通过”。

## Windows 11 x86-64

- 当前仓库的 Windows 构建入口：`windows-client/Build-IdenGrid-Windows.ps1`；命令及所需独立运行时清单摘要、Brave 归档、媒体门禁结果见 [README.md](../README.md#本地开发与验证)。这是**便携目录构建**，不是安装器。脚本发布 `IdenGrid.Windows.Wpf.csproj` 并复制/复核 Brave 运行时，但**没有将 Rust `idengrid-agent.exe` 复制进便携目录，也没有完成签名或 ZIP 归档**；历史内部测试包的完整组装流程尚未在该脚本中复现。接手者须补齐并验证可复现的受控打包入口；在此之前不得把单独运行脚本的输出称作完整可交付包。最终目录必须实测包含 `IdenGrid.Windows.exe`、`Components/Browser/brave.exe`、`Components/idengrid-agent.exe`、扩展和运行时 Manifest。缺任一项不得交付。
- 浏览器来源、官方可执行文件签名、归档/清单的独立摘要及逐文件匹配必须与**这次**交付包绑定；检查签名证书属于内部还是公众信任。不能凭文件名或旧结果宣称当前包可信。Brave 的技术兼容性不自动赋予再分发/商标/编解码器权利，正式对外发布前须另行确认授权。
- 在真实 Windows 11 交互会话：先按完整 `ExecutablePath` 确认旧版管理客户端、Brave 和 Agent 均已退出，避免把旧版子进程误算成新版。由最终 ZIP 解压出的**确切管理客户端**启动、登录或恢复会话、显示授权店铺、从 UI 启动店铺，核对包内 Agent/Brave 的实际完整路径。Windows Agent 配置经 stdin 输入，控制通道为本地 Named Pipe；`windows-client/tests/Static/test_windows_agent_packaging.py` 仅检查源码字符串与 CRT 选项，不证明实际 DACL。须在 Windows 实机验证当前用户可控、另一用户被拒和 Agent 失联 Fail Closed。
- 检查本机 SOCKS、授权 Edge 固定出口与直连出口对照、实际浏览器 HTTPS、DNS/WebRTC/QUIC 防泄漏、独立 Profile/Cookie、下载路径、关闭与 Agent 中断后的 Fail Closed、正常重启后的恢复。`curl --proxy socks5h` 仅证明 Agent 的出口路径；浏览器泄漏测试要在真实页面/浏览器上下文另做。
- 新鲜密码登录和 `429 Retry-After` 倒计时属于**单独的 UI 验收项**；SDK 登录后恢复 DPAPI 会话不等于这两项通过。需要测试密码时只在受控交互界面输入，禁止写入脚本、命令行、环境变量或日志。
- 内部证书签名的 ZIP 只能标“内部测试版”；未完成公众代码签名、信誉与目标干净机器门禁时不能称正式安装包。保留 ZIP 的实际路径和 SHA-256，清除一次性脚本/计划任务，勿清理用户 Profile 或已交付目录。

## Apple Silicon macOS

- `native-client/release/scripts/build-dev-arm64.sh` 构建本机 ad-hoc 签名开发 `.app`；不是正式 DMG，也未公证。先运行 `native-client/release/scripts/verify-on-apple-silicon.sh` 检查 Swift/Rust 工具链与源码合同，再用受控的非秘密 HTTPS API 地址构建开发包。`build-arm64.sh` 仅组装应用；`check-licenses-sbom.sh`（需要 `syft`）、`sign-nested.sh`、`notarize-staple-dmg.sh` 分别处理正式发布的许可/SBOM、Developer ID 签名、公证 DMG。具体输入、路径与顺序见 [macOS 组件说明](../native-client/macos/README.md)；运行时架构和包内版本要从**实际产物**读取。
- `native-client/macos/Tests/Static/check_contract.sh` 必须在默认输出目录还没有 `IdenGrid.dmg` 时执行；它会故意拒绝已有 DMG。不能把公证后此脚本失败误报为产品回归，也不能删除现有 DMG 只为让静态测试变绿。
- 构建输入包括受控 API 地址、Apple Silicon Agent、Chromium 清单及更新/签名材料；不可把开发版随机 Sparkle 公钥当正式更新密钥。正式发布前完成第三方许可/SBOM、Developer ID 和公证，并在目标 Mac 上检查实际签名和可运行性。
- 实机核对店铺隔离、出口、DNS/WebRTC/QUIC、Profile 持久化、Token 刷新、断链 Fail Closed、窗口/Dock 身份和关闭流程。不要把静态源测试、单独 Chromium 启动或签名工具返回码当作整套客户端通过。

## 历史验收如何引用

[HANDOFF.md](../HANDOFF.md) 载有截至 2026 年 10 月的有限历史结论。每个新包仍需重新执行相关门禁；未重跑的项目写“历史证据，仅供参考”。日志/截图只保留脱敏的状态与版本，不能包含密码、Token、Cookie、页面私密内容或带能力的 URL。
