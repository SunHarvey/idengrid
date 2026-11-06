# IdenGrid 交接索引（公开版）

> 这是源码与验收边界的交接说明，不是生产资产清单。接手前先核对实际分支、版本、环境与授权；不能把一次历史验收当作当前在线状态。本文不包含真实域名、IP、账号、能力型下载地址、密钥或连接串。

## 先读什么

1. [README.md](README.md)：产品架构、目录和最小测试命令。
   [AI Agent 对话决策摘要](docs/AI-AGENT-HANDOFF.md)：本轮协作中已确认的约束、历史证据与接手停止条件（不是生产台账）。
2. [运维与恢复](docs/OPERATIONS.md)：控制端、数据库和 Edge 的配置来源、变更/回滚门禁。
3. [构建与验收](docs/RELEASE-ACCEPTANCE.md)：macOS/Windows 构建入口、证据等级、逐项门禁。
4. 组件说明：[Rust Agent](native-client/agent-rs/README.md)、[macOS](native-client/macos/README.md)、[Linux Edge](edge-tunnel/README.md)、[Windows Edge](windows-edge/README.md)。
5. [SECURITY.md](SECURITY.md)、[LICENSE](LICENSE)、[TRADEMARKS.md](TRADEMARKS.md)：安全报告、许可和品牌边界。

## 项目边界

- 控制端：`cloudbrowser/`（FastAPI、数据库、用户/授权/租约/票据/审计）。部署模板在 `deploy/`，公开配置样例在 `config/`。
- 数据面：`native-client/agent-rs/` 的每店铺 Rust Agent，经认证的 WSS 连接到 `edge-tunnel/` 或 `windows-edge/`；浏览器从本机独立 Profile 经过回环 SOCKS 出口。
- 客户端：`native-client/macos/` 是 Apple Silicon SwiftUI；`windows-client/src/IdenGrid.Windows.Wpf/` 是 Windows 11 x64、.NET 10/WPF。`windows-client/src/IdenGrid.Windows/` 还有旧 UI 工程，不要仅按目录名推断实际打包入口；以 `windows-client/Build-IdenGrid-Windows.ps1` 为准。
- 浏览器运行时、Agent、管理客户端和安装/归档是不同交付层。单独启动 Brave 或验证 ZIP 哈希，不等于完整客户端通过。
- 每个用户/设备/店铺的 Profile、Cookie、Agent、控制通道和租约应隔离；授权失败、代理/Edge 断开或出口校验失败必须 Fail Closed。不要让新旧机器同时使用同一份活动 Profile。

## 接手时的第一轮核对（只读）

1. 记录 `git status --short --branch`、`git log -1 --format='%H %s'`，保留任何未提交改动；确认实际部署版本是否来自该提交，**不能由仓库 HEAD 推断生产已升级**。
2. 阅读上述文档和 `config/*.example*`；向资产负责人通过受保护渠道索取**环境清单的保管位置和访问权限**，而不是将配置/凭据写入聊天、Issue、提交或日志。
3. 分别核对控制端/数据库/Edge 的服务状态与备份可恢复性，客户端实际可执行文件路径、包摘要和签名身份；任何部署或清理前先确定回滚对象。
4. 先跑本地测试，再在真实目标系统验证。区分“源码测试”“包完整性”“运行时”“完整业务链”，在验收记录中注明日期、版本、设备和未测项。
5. 先确定功能范围，再改架构；不要把 Windows 测试机、远端下载校验主机或生产 Edge 混为一个节点，也不要在生产 Edge 主机编译完整 Chromium。

## 版本与证据状态（历史记录，非实时探测）

- Linux Edge 打包修复已提交到 GitHub `main`：`0de8ea262d6f978be85d5b137a98226a7a3ede8a`。这是**源码提交**，不是已发布 tar 的摘要，也不能证明生产已升级；接手时仍须读取实时 HEAD 和部署台账。
- 2026 年 10 月的既有验收记录：生产服务端曾验证原生登录前四次失败返回 401、第五次 429 且 `Retry-After=300`；Windows 11 上用内部测试包 `IdenGrid-Windows-Brave-v0.2.5-internal-test.zip`（SHA-256 `c3783b1d2dafb58c316d560c80d741f8a5d30846cf29d4db9ffdfdc81fff3dac`）验证了新版 WPF 会话恢复/授权店铺启动、包内 Agent/Brave、经 Agent 的固定出口和终止 Agent 后浏览器退出，并重新启动店铺。Brave 版本为 1.97.59；内部签名**不是**公众受信发布签名。该记录仅说明当次测试，不保证现在仍在运行或包仍可下载。
- 上述 Windows 客户端验证**不等于**在 WPF 界面重新输入密码登录；也没有证明 429 倒计时 UI、浏览器级 DNS/WebRTC/QUIC 防泄漏、跨设备同步、全部店铺或公众发布门禁已通过。经 `curl --proxy socks5h` 的固定出口证明数据通道，不替代浏览器防泄漏验收。
- 当前实际生产版本、数据库备份有效性、Edge 健康、Windows/macOS 构建与证书有效期均需接手者重新读取；不能从此文档推断。
- **已知交付缺口（Windows）**：当前 `windows-client/Build-IdenGrid-Windows.ps1` 没有把 Rust Agent 装入便携目录，也不完成签名/ZIP 归档；历史内部测试包的完整组装不能仅凭此脚本复现。具体门禁见 [构建与验收](docs/RELEASE-ACCEPTANCE.md)。
- **Linux Edge 包修复状态**：`scripts/build_edge_package.py` 现把运行时导入的 `edge_tunnel/config.py`、`edge_tunnel/resources.py` 纳入清单；回归测试从新生成的 tar 独立解压并导入服务入口。本机另已核对包与 `.sha256`、安装解压包后隔离导入、从解压包启动回环 `/healthz`（200）。相关定向测试 164 项通过、Ruff 通过；扩大测试未取得全套通过结论。**这些证据不等于已发布可下载产物，也不等于干净 Rocky Linux 目标机的登记、systemd、Caddy、TLS 与回滚验收。**复现命令和发布门禁见 [构建与验收](docs/RELEASE-ACCEPTANCE.md)及[运维与恢复](docs/OPERATIONS.md)。
- **尚存的登录安全缺口**：持久化限流只覆盖 `/api/native/login`，管理网页的 `/api/login` 未实施同等限流；历史“第五次 429”只适用于原生入口。需单独修代码与测试，不能靠文档措辞视为已解决。见 [运维安全边界](docs/OPERATIONS.md#安全边界与事故处理)。
- **当前缺少可复核的交付链**：历史 Windows ZIP 的摘要只是点时证据；公开仓库没有独立托管的完整包/逐项验收证据目录，也不包含受保护的生产资产台账。取得授权后应核对产物的保管位置、实际字节/签名和环境记录，不要用公开文档替代。

## 下一位接手者应留下的记录

每次变更在受保护的运维记录中写：目标环境、源码提交、产物版本/哈希、配置版本（不写值）、审批和回滚负责人、备份及恢复演练、测试逐项结果、部署前后健康、失败和残留问题。公开仓库只保留匿名化摘要与可复现命令；绝不提交生产环境文件、Token、私钥、Profile/Cookie 或能力型下载 URL。当前还没有一个可替代受保护资产台账的仓库文件，生产接管必须由资产负责人另行授权。
