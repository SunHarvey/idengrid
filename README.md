# IdenGrid · 澜序

[中文](README.md) | [English](README_EN.md)

**跨平台浏览器工作空间，提供独立环境与受控固定出口。**

**环境独立，协作从容。**

IdenGrid（澜序）用于在 macOS 和 Windows 上管理相互隔离的浏览器工作空间。每个工作空间拥有独立的浏览器 Profile、本地 Agent、连接租约和经过授权的 Edge 出口。

## 架构

```text
macOS／Windows 客户端
  → 本地 Chromium 独立 Profile
  → 本机回环 SOCKS
  → 每个工作空间独立的 Rust Agent
  → 经过认证的 WSS 通道
  → 管理员授权的 Edge 节点
  → 固定公网出口
```

控制端负责用户、设备、工作空间授权、连接租约、一次性票据、审计和 Edge 健康状态。浏览器 Profile、Cookie 和本地浏览数据保留在用户设备上，不在不同设备之间共享同一份 Profile。

## 主要组件

- `cloudbrowser/`：FastAPI 控制端
- `edge-tunnel/`：基于 Python／aiohttp 的认证 Edge 转发服务
- `native-client/agent-rs/`：跨平台 Rust Agent
- `native-client/macos/`：Apple Silicon SwiftUI 客户端
- `windows-client/`：Windows 11 x86-64 .NET／WPF 客户端
- `config/`：公开配置模板
- `tests/`：控制端及客户端契约测试

## 配置方式

生产环境的域名、数据库连接、节点地址和凭据均不写死在源码中。部署时从以下示例文件创建实际配置：

```text
config/control.env.example
config/caddy.env.example
config/bootstrap.example.json
config/local-environment.example.json
config/client.example.json
```

真实生产配置必须保存在受保护的部署文件中。Mac 和 Windows 客户端使用的控制端地址在构建时注入应用资源，不提供源码内的生产地址回退。

## 本地开发与验证

### 控制端

```bash
uv sync --dev
uv run ruff check cloudbrowser scripts tests
uv run pytest -q
```

### Rust Agent

```bash
cd native-client/agent-rs
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

### macOS 客户端

静态契约测试：

```bash
pytest -q native-client/macos/Tests/Static
```

Apple Silicon 构建需要 macOS Command Line Tools，以及 `native-client/release/scripts/` 中的构建脚本。构建前设置：

```bash
export IDENGRID_API_BASE_URL="https://api.example.com/"
```

如需签名更新，还需要设置 `IDENGRID_UPDATE_FEED_URL`。这些值会在构建时写入应用资源。

### Windows 客户端

静态契约测试：

```bash
pytest -q windows-client/tests/Static
```

完整 WPF 构建需要 Windows 和 .NET 10：

```powershell
$env:IDENGRID_API_BASE_URL = "https://api.example.com/"
.\windows-client\Build-IdenGrid-Windows.ps1
```

构建脚本会验证 HTTPS 地址，并通过临时配置资源完成注入，不修改仓库中的示例配置。

## 安全原则

- 路由、身份、容量、票据或出口验证失败时统一 Fail Closed
- Token 和凭据不得出现在命令行参数或日志中
- 每台设备、每个工作空间分别维护 Profile、Cookie、Agent、控制通道和租约
- 普通用户只能连接管理员授权的 Edge 节点
- 审计不记录页面内容、Cookie、密码或 HTTPS URL 路径
- 节点异常时不得回退本机公网或自动切换到未授权出口

安全问题报告方式请参阅 [SECURITY.md](SECURITY.md)。

## 授权

本项目采用源码可见的非商业授权模式：

- 非商业用途可以免费使用
- 修改版对外分发或通过网络提供服务时，必须公开对应源码
- 任何商业使用都必须取得版权方的书面商业授权
- IdenGrid、澜序、Logo 和其他品牌资产不包含在代码授权中

完整条款请参阅：

- [IdenGrid Community License](LICENSE)
- [商业授权说明](COMMERCIAL-LICENSE.md)
- [品牌与商标说明](TRADEMARKS.md)

该许可证不属于 OSI 批准的开源许可证。
