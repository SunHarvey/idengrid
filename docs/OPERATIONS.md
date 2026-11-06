# 运维与恢复门禁（公开版）

本文只说明入口和操作顺序，不提供生产地址、凭据或一键改动命令。执行者必须先从受保护资产台账核实实际主机、工作目录、服务名、数据库与备份位置。仓库的 `deploy/` 是模板，不应假定与运行中的机器完全一致。

## 配置与服务映射

- 控制端：`deploy/idengrid-control.service`，代码入口 `cloudbrowser.main:app`；模板从 `/etc/idengrid/control.env` 读取配置，以 `idengrid-control` 用户运行。公开示例是 `config/control.env.example`。
- HTTPS 网关：`deploy/idengrid-control-caddy.service` 与 `deploy/Caddyfile`；模板从 `/etc/idengrid/caddy.env` 读取配置。控制端/网关的实际代理和证书配置必须在目标机上复核。
- MySQL 8.4：`deploy/mysql/compose.yaml`、`my.cnf`、`init/`、`mysql.env.example`；Compose 模板只绑定 `127.0.0.1:3306`，持久卷为 `idengrid-mysql-data`。生产数据库以实际部署配置为准；不要从旧 SQLite 回滚备份推断当前业务数据。
- Edge 健康：`deploy/idengrid-edge-health.service` 与 `.timer`、`scripts/monitor_edge_health.py`。
- Linux Edge：`edge-tunnel/README.md`；Windows Server Edge：`windows-edge/README.md`。两种服务的部署、升级/回滚入口不同，不可混用。
- 环境相关值通过受保护文件或构建参数注入；绝不在源码、命令行、Issue、聊天或普通日志中写入密码、Token、节点密钥、数据库 URL 或能力型下载链接。原有 `SECRET_KEY` 必须保持不变，除非另行设计和审批完整密钥轮换。

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

- 登录限流由服务端执行；客户端 `429/Retry-After` 显示属于独立 UI 门禁。登录失败和审计不得写入密码、Token、Cookie 或 HTTPS 路径。
- Edge/控制端节点故障不能自动退回本机公网或换到未经授权的 Edge。先保全故障现场，分别检查授权、租约、Agent、WSS、出口和 DNS，勿以禁用安全约束换取“可用”。
- 生产变更记录中的主机、配置保管人、备份位置和恢复凭据只存于受控系统；公开仓库中的 `.example` 使用占位值。访问权缺失时停止生产操作并申请授权，不能猜测配置。
