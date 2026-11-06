# 运维与恢复门禁（公开版）

本文只说明入口和操作顺序，不提供生产地址、凭据或一键改动命令。执行者必须先从受保护资产台账核实实际主机、工作目录、服务名、数据库与备份位置。仓库的 `deploy/` 是模板，不应假定与运行中的机器完全一致。

## 配置与服务映射

- 控制端：`deploy/idengrid-control.service`，代码入口 `cloudbrowser.main:app`；模板从 `/etc/idengrid/control.env` 读取配置，以 `idengrid-control` 用户运行。公开示例是 `config/control.env.example`。
- HTTPS 网关：`deploy/idengrid-control-caddy.service` 与 `deploy/Caddyfile`；模板从 `/etc/idengrid/caddy.env` 读取配置。控制端/网关的实际代理和证书配置必须在目标机上复核。
- MySQL 8.4：`deploy/mysql/compose.yaml`、`my.cnf`、`init/`、`mysql.env.example`；Compose 模板只绑定 `127.0.0.1:3306`，持久卷为 `idengrid-mysql-data`。生产数据库以实际部署配置为准；不要从旧 SQLite 回滚备份推断当前业务数据。
- Edge 健康：`deploy/idengrid-edge-health.service` 与 `.timer`、`scripts/monitor_edge_health.py`。
- Linux Edge：`edge-tunnel/README.md` 是**源树安装**说明；控制端登记下发的 `scripts/edge-install.sh` 使用由 `scripts/build_edge_package.py` 产生的 tar 包，属于另一条安装路径。打包清单已补齐 `edge_tunnel/config.py`、`edge_tunnel/resources.py`，并新增从解压包导入服务入口的回归测试；本机隔离回环启动 `/healthz` 已通过。**这些检查不等于干净 Rocky Linux 主机的完整登记、服务、网关、TLS 或回滚验收**，发布前还需绑定新包摘要并执行目标机门禁。Windows Server Edge 见 `windows-edge/README.md`：正式 `-Server` 从获批注册 claim 构造受保护配置；`-LabConfig` 才使用预先保护的 `-ProtectedConfigPath`，两种流程不得混用。
- 环境相关值通过受保护文件或构建参数注入；绝不在源码、命令行、Issue、聊天或普通日志中写入密码、Token、节点密钥、数据库 URL 或能力型下载链接。原有 `SECRET_KEY` 必须保持不变，除非另行设计和审批完整密钥轮换。
- `config/bootstrap.example.json` 所示拓扑是**首次建库种子**：应用写入 `bootstrap_topology_applied_v1` 后不会因编辑种子文件并重启而重新应用。`BOOTSTRAP_ADMIN_USERNAME`/`BOOTSTRAP_ADMIN_PASSWORD` 仅在该用户名尚不存在时建号，不会轮换现有管理员密码。已有用户、店铺、节点或授权应经受控管理流程变更；不要清除种子标记或重新生成 `SECRET_KEY` 来强迫重播。

## 控制端登记产物与文件布局

`deploy/idengrid-control.service` 默认从 `/opt/idengrid` 运行，但登记/下载接口在 `cloudbrowser/app.py` 直接读取 Linux tar `/data/dist/edge-tunnel.tar.gz` **及其旁置** `/data/dist/edge-tunnel.tar.gz.sha256`；Windows Edge 则读取 `/data/dist/release-manifest.json`、`/data/dist/release-manifest.json.sig` **及该已签名清单命名的同目录版本化 ZIP**。还读取 `/data/windows-edge/scripts/Install-IdenGridEdge.ps1` 以及 `/data/scripts/install-edge.sh`、`/data/scripts/edge-install.sh` 等固定路径；Linux 安装脚本也经控制端分发。**只复制仓库到 `/opt/idengrid` 并启用 systemd 服务并不能提供这些产物。**缺失或不匹配的 Linux 旁置摘要会导致控制端拒绝提供包；Windows ZIP 的大小与摘要须与已签名清单一致。受保护部署台账须记录谁构建、审查、签名、校验与放置各文件、实际服务用户的读取权限以及 Caddy/API 对外路由；发布前依次只读核对成套文件、摘要/签名及服务端响应。绝不能为“补齐目录”复制未验证的旧包或把私钥放入这些目录。Linux Edge 新包虽已通过本机解压导入/回环健康检查，目标主机安装链仍需另行验收。

**Linux Edge 新包交接**：在隔离目录从待发布提交重新构建并校验 `.sha256`（入口和本机测试见 [构建与验收](RELEASE-ACCEPTANCE.md)）；把该次 tar 的完整 SHA-256 与控制端登记 claim 中的 `package_sha256`、实际下载字节及受保护发布记录逐一对应。源码提交、旧 tar、旁置校验文件和控制端当前提供的字节不可相互替代。`scripts/edge-install.sh` 校验下载包后会清空 `/opt/edge-tunnel/*` 再解压、安装 Python 包、写入配置并启用服务；还会**覆盖 `/etc/caddy/Caddyfile`**。先审查是否共用网关，备份网关配置并验证恢复方案；共享 Caddy 的主机不能直接运行这一安装器。只能在已批准的干净目标机或具备快照和回滚方案的维护窗口执行。不得为了补齐 `/data/dist` 而直接上传未经批准的新包；尚无目标机实测记录。

## 自动建表/迁移边界

控制端在应用启动过程中执行 `Base.metadata.create_all(engine)` 和 `cloudbrowser/schema.py` 中的 MySQL/Edge 迁移，并可能 `ALTER TABLE` 增列（`cloudbrowser/app.py`）。这不是一个可单独回滚的版本化迁移链。升级前逐项对照旧/新模型和 `cloudbrowser/schema.py`，在隔离的同版本备份副本上模拟**启动 DDL 与旧程序回退**，记录表/索引/约束变化、兼容性、服务中断窗口、备份校验及授权的恢复点；审查没有完成时不要先重启新代码。回滚代码不代表数据库已回滚；不可在生产库直接尝试 `DROP`/重导入以“验证”回滚。若模型变更不可逆，先形成经批准的前向修复或离线恢复方案。

## Linux Edge 安装的宿主机副作用

`scripts/edge-install.sh` 除服务和 Caddy 外，还会覆盖 `/etc/caddy/Caddyfile`、修改 firewalld 规则、SSH 登录策略、journald 限额，并在无 swap 时创建 swapfile；有些步骤是宿主机级、不能靠回滚应用目录自动撤销。安装前采集现有 Caddy/firewall/SSH/journald/swap 状态，审查对现有远程管理通道和其他服务的影响；故障回滚以**变更前快照及资产负责人审批**为依据，只撤销本次确实引入的规则/文件，验证 SSH 与服务存活。禁止在未知主机上直接重跑安装脚本或用猜测的反向命令清理系统设置。

## 生产变更顺序

1. **冻结范围并取证**：确认目标环境、当前运行提交/产物摘要、实际服务状态、数据库类型与连接方式、Edge 授权关系和可回滚版本；留存匿名化基线。只读检查先于任何上传或重启。
2. **确认备份可恢复**：由具备权限的运维人员用受保护方式制作并验证 MySQL 一致性备份和相关配置的安全备份；记录时间、大小、摘要和异机恢复验证。不要把旧 SQLite 文件当作持续更新的 MySQL 备份，也不要在生产上试恢复覆盖现有库。
3. **隔离准备**：在非生产环境以相同配置形状执行测试；升级前校验所有产物哈希、签名、第三方运行时清单和依赖。仅上传当前变更所需文件，不覆盖受保护配置。
4. **按依赖部署**：需要数据库变更时先确认兼容性和迁移/回滚策略；再更新控制端和相应 Edge/客户端。对每个目标单独记录启动/重载命令、版本和结果。禁止同时让新旧主机写同一份 Profile 或无控制地双活同一服务状态。
5. **真实验收**：服务健康、数据库连接、授权列表、登录与限流、租约/票据、经 Agent 的固定出口、失联 Fail Closed、审计脱敏；客户端另按 [构建与验收](RELEASE-ACCEPTANCE.md) 在目标系统验收。公网健康检查不能替代真实店铺链路。
6. **回滚与复核**：若门禁失败，停止后续发布，在明确的数据兼容边界内切回已知可用的代码/产物；数据库只从经过验证的备份按审批执行恢复。回滚后再次检查健康、数据一致性和授权行为，记录残留问题。

## SQLite → MySQL 迁移仅供新环境参考

`scripts/migrate_sqlite_to_mysql.py --help` 提供迁移选项；其目标 URL 可以来自仅所有者可读的 `--target-file`，并支持 `--dry-run` 与 `--report-file`。`--reset-empty-destination` 明确包含删除目标模型表的动作，不应在现有生产库上试用。**已有生产实例完成过迁移，不应在接手时重新执行迁移。**另见 `tests/test_sqlite_to_mysql_migration.py` 和 `tests/test_mysql_support.py`。备份、断写窗口、源/目标行数与指纹核对、恢复演练必须在正式迁移计划中逐项确认。

## 安全边界与事故处理

- **入口范围待修复**：持久化登录限流和 `429/Retry-After` 仅在原生客户端 `/api/native/login` 服务端实现；管理网页使用的 `/api/login` 目前只有失败审计与 401，**没有相同的限流保护**。不能以原生入口测试证明网页入口安全；网页限流需要单独设计、实现和验证，客户端倒计时显示也属于独立 UI 门禁。登录失败和审计不得写入密码、Token、Cookie 或 HTTPS 路径。
- Linux Edge 的源码 Caddy 模板及登记安装器生成配置**未配置 JSON 访问日志脱敏规则**。如目标机另行启用访问日志，先审查实际 Caddy 配置和采集链，不得记录 Authorization、票据、查询参数或完整敏感 URL；不能从模板推断日志已脱敏。
- Edge/控制端节点故障不能自动退回本机公网或换到未经授权的 Edge。先保全故障现场，分别检查授权、租约、Agent、WSS、出口和 DNS，勿以禁用安全约束换取“可用”。
- 生产变更记录中的主机、配置保管人、备份位置和恢复凭据只存于受控系统；公开仓库中的 `.example` 使用占位值。访问权缺失时停止生产操作并申请授权，不能猜测配置。
