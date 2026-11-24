# Johnny Bot Go 服务接入指南

Johnny Bot 在内网运行。Go 进程管理 ACP Agent、SQLite 数据库和嵌入式 Mochi MQTT broker。设备把选定的数据范围同步到本地 SQLite，界面始终从本地库读。断网时，设备可以打开已缓存的列表和会话，保存待发送消息。联网后，服务端执行这些命令并同步结果。

同步范围借鉴 Realm Flexible Sync 的订阅模型。Johnny Bot 使用固定的工作区和会话范围，服务端分配事件序号并接受明确的业务命令。 [Realm Core](https://github.com/realm/realm-core) · [Realm 订阅示例](https://www.mongodb.com/docs/atlas/device-sdks/studio/view-atlas-data-sync/)

## 1. 安装和启动

需要 Linux 或 macOS、Go 1.27.4、启用 CGO 并安装 C 编译器、Node.js 和 `npx`。SQLite 由 Go 驱动编译进服务端。运行服务的系统用户应已完成所用 Agent 的登录。默认启动 Codex，使用 `npx -y @agentclientprotocol/codex-acp@latest`。pi 通过 `npx -y pi-acp@latest` 启动。

```sh
go build -buildvcs=false -o bin/johnnybot ./cmd/johnnybot
./bin/johnnybot serve -addr 0.0.0.0:8883 -host laptop \
  -data "$HOME/.config/johnnybot" \
  -workspace "app=$HOME/dev/app" \
  -workspace "notes=$HOME/dev/notes"
```

`-workspace` 可重复使用。ID 匹配 `[A-Za-z0-9_-]{1,80}`，配置内唯一，客户端持久化后应保持稳定。省略时用 `default` 和当前目录。启动输出给出 MQTT 地址、topic 中的 host、TLS 证书指纹和设备密钥文件路径。在启动服务前也可以用本地 CLI 检查 adapter。

```sh
./bin/johnnybot sessions -agent codex
./bin/johnnybot chat -agent codex -cwd "$HOME/dev/app"
```

服务的数据目录包含 `host.pem`、`authorized_keys`、`johnnybot.db` 和 SQLite 的 WAL 文件。同一数据库只允许一个服务进程。每个获准设备都属于同一用户，拥有已配置工作区的访问权。工作区限制的是服务 API 的路径范围，ACP 子进程的系统权限由运行它的用户和 adapter 自身控制。

## 2. 设备配对、TLS 和 MQTT 连接

1. 在设备上生成独立 Ed25519 密钥对，将私钥存入 Keychain。在 Swift 可用 `Curve25519.Signing.PrivateKey()`。用同一密钥重连以保留设备身份和命令去重记录。
2. 将公钥以 OpenSSH 格式追加到服务器的 `authorized_keys`。一行写 `ssh-ed25519 BASE64 comment`。BASE64 的内容是两个 SSH string，分别为 ASCII `ssh-ed25519` 和 32 字节原始公钥。每个 string 前面有一个 4 字节大端长度。也可以用 `ssh-keygen -t ed25519` 为测试设备生成密钥。删除对应公钥后，服务通常在两秒内断开该设备。
3. 通过可信渠道配对地址、host 和服务端指纹。连接 MQTT 5 over TLS 1.3，验证对端叶证书 DER 的 SHA-256 十六进制与配对指纹完全相等。证书是服务本地生成的。信任回调必须在指纹不同、缺失证书或无法计算指纹时终止握手。
4. MQTT Client ID 是原始公钥 SHA-256 的前 16 字节转小写十六进制。Username 为 `ed25519-v1`。每次 CONNECT 重新生成签名和 nonce。关闭 Will，建议 `Clean Start = true`，使用应用层增量同步补回遗漏数据。
5. 先订阅设备自己的 reply topic，等 SUBACK 后再发命令。订阅当前已选 scope 的更新提示，接着执行 `ping` 和每个 scope 的 `sync.pull`。

签名原文由下列五行 UTF-8 文本组成，最后一行没有换行。

```text
johnnybot-mqtt-auth-v1
<64 个小写十六进制字符的证书指纹>
<32 个小写十六进制字符的设备 ID>
<当前 Unix 秒数，十进制>
<16 字节随机数的无 padding Base64URL>
```

Password 为 `<秒数>.<nonce>.<签名的无 padding Base64URL>`，签名使用 Ed25519 原始签名的 64 字节。服务允许正负两分钟的时间偏差。以下 Swift 代码示例生成认证字段，证书回调由选用的 MQTT 客户端接入。

```swift
import CryptoKit
import Foundation

func base64URL(_ bytes: Data) -> String {
    bytes.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func mqttCredentials(
    key: Curve25519.Signing.PrivateKey,
    pinnedFingerprint: String
) throws -> (clientID: String, username: String, password: String) {
    let deviceID = SHA256.hash(data: key.publicKey.rawRepresentation)
        .prefix(16).map { String(format: "%02x", $0) }.joined()
    let seconds = String(Int64(Date().timeIntervalSince1970))
    var rng = SystemRandomNumberGenerator()
    let nonce = base64URL(Data((0..<16).map { _ in
        UInt8.random(in: .min ... .max, using: &rng)
    }))
    let message = ["johnnybot-mqtt-auth-v1", pinnedFingerprint,
                   deviceID, seconds, nonce].joined(separator: "\n")
    let signature = try key.signature(for: Data(message.utf8))
    return (deviceID, "ed25519-v1", "\(seconds).\(nonce).\(base64URL(signature))")
}
```

| Topic（前缀 `jb/v1/{host}/`） | 方向 | QoS | 内容 |
| --- | --- | --- | --- |
| `cmd/{device_id}` | 设备 → 服务 | 1 | UTF-8 JSON 命令 |
| `reply/{device_id}` | 服务 → 设备 | 1 | 同一 `cmd_id` 的应用结果 |
| `ev/threads/{workspace_id}` | 服务 → 设备 | 1 | 该工作区列表有变更的提示 |
| `ev/thread/{thread_id}` | 服务 → 设备 | 1 | 该会话有变更的提示 |

命令必须关闭 retained。变更提示只有 `{"scope":"thread/…","epoch":"…"}`，可重复或丢失。订阅范围是带宽和缓存选择。同一个用户的设备可显式拉取任何已配置工作区的数据。

## 3. 命令、重试和错误

每个命令是单独的 JSON 对象。所有命令要求唯一的 `cmd_id`，格式与工作区 ID 一致。建议用随机 UUID。请求上限 128 KiB，MQTT 包上限 256 KiB。下面为操作格式，常规请求应省略未使用的字段。

```json
{"cmd_id":"new-01","op":"thread.create","epoch":"<ping 的 epoch>","workspace_id":"app","path":".","agent":"codex","title":"调试登录"}
```

```json
{"cmd_id":"new-01","ok":true,"result":{"thread_id":"<id>","workspace_id":"app","agent":"codex","session_id":"<ACP id>","path":".","title":"调试登录","updated_at":"2026-11-24T14:00:00.000000000Z","archived":false,"history_imported":true}}
```

```json
{"cmd_id":"send-03","ok":false,"error":{"code":"thread_busy","message":"thread already has an operation in progress"}}
```

写操作要求当前 `epoch`。收到成功的 MQTT PUBACK 代表服务已接收写命令到持久化队列。业务结果在 reply topic 返回。若断线、超时或没收到应用结果，按原字节重发，包括原 `cmd_id`。相同设备和 ID 的相同请求只认第一次入队，最终会重放原结果。相同 ID 的不同请求收到 `command_conflict`。读请求可重新生成 ID。客户端同一个 thread 的后续写操作应等前一写操作的完成结果，多个设备并行修改同一 thread 时可能得到 `thread_busy`。多个 thread 可并行运行。

| 操作 | 类型 | 参数和结果 |
| --- | --- | --- |
| `ping` | 读 | 返回 `time`（Unix 毫秒）、`epoch`。 |
| `workspaces.list` | 读 | 返回可见工作区 ID 数组、可选 Agent 名称和 epoch。适合连接后刷新并缓存。 |
| `directories.list` | 读 | 要求 `workspace_id`，可带相对 `path`、`name_after`。返回 `path`、`parent`（到根为 null）、按名称排序的 `directories` 和 `more`。继续时用末项作 `name_after`。 |
| `file.read` | 读 | 要求 `thread_id` 和项目相对 `path`。首次 `offset=0`，继续时提交上页 `next_offset` 和 `version`。结果含标准 Base64 的 `bytes`、`next_offset`、`version`、`more`。返回 `file_changed` 时清理暂存并从头读。 |
| `sync.pull` | 读 | 要求 `scope`，支持 `epoch`、`after`、`through`、`limit`。见同步章节。 |
| `thread.refresh` | 写 | 要求 `workspace_id`、可选 `agent`（默认 codex），从 ACP 分页列出本地会话，登记此工作区内尚未收录的会话。返回 `found`，随后拉取列表。 |
| `thread.create` | 写 | 要求 `workspace_id`，可选相对 `path`、`agent`、`title`。返回 thread 对象，同时生成列表事件和 `session.setup`。 |
| `thread.open` | 写 | 要求 `thread_id`。首次打开尝试导入 Agent 的已有会话历史。返回 thread 对象。留意 `history_imported`。 |
| `thread.rename` | 写 | 要求 `thread_id`、非空 `title`（最多 512 UTF-8 字节）。返回更新后的本地列表状态。 |
| `thread.archive` | 写 | 要求 `thread_id`、`archived` 布尔值。归档期间不能发送 prompt，历史仍可读取。 |
| `prompt.send` | 写 | 要求 `thread_id` 和 `prompt`（1 至 32 个 ACP content block）。例如 `[{"type":"text","text":"请检查配置"}]`。结束时返回 `turn_id`、`status`、`stop_reason`。 |
| `turn.cancel` | 写 | 要求 `thread_id`、`turn_id`。收到结果后继续同步，直到看到 `turn.finished`。适合在线发送。 |
| `permission.answer` | 写 | 要求 `thread_id`、`turn_id`、`permission_id`、请求中列出的 `option_id`。同一审批第一个有效答复生效，其余返回 `permission_closed`。适合在线发送。 |

路径为服务器本地相对路径，根目录用 `.`。目录请求只能选择工作区范围内的目标。文件读取是长度受限的按需请求，文件内容不会自动同步。 `not_found` 表示数据或路径不存在，`invalid_argument` 表示参数不合法，`thread_archived` 要求先取消归档，`not_active` 说明取消动作对应的 turn 已结束。 `server_busy` 和 `thread_busy` 可等状态变化后由用户创建新命令。 `interrupted` 意味着服务无法确认之前的操作是否完成，先同步并检查真实状态，尤其是工具已产生外部效果时。 `epoch_mismatch` 要求重新读数据库世代，并按下面规则隔离旧出站队列。 `internal` 详情在服务日志中。

## 4. 选择性同步

客户端维护一组 scope，互相独立地选择和同步。

- `threads/{workspace_id}` 包含该工作区的列表元数据变化。按 `thread_id` upsert 到本地 thread 表，可用 `archived` 和 `updated_at` 筛选或排序。首页可只选正在关注的工作区。
- `thread/{thread_id}` 包含该会话的内容和运行状态。进入会话时选择，或允许用户显式标记为离线可用。取消选择时取消订阅，可按产品需要删除对应的本地缓存及游标。将已缓存的 thread 与未下载状态分开展示。
- `workspaces.list` 和 `directories.list` 按需拉取。需要离线展示目录时，可按 `workspace_id` 和相对路径单独缓存。目录分页是活动文件系统浏览，分页期间的并发移动可能改变结果。已读文件也可由客户端主动缓存。

首次用 `after=0` 取一页。初次 `through` 省略或设置为零，服务把它固定成当时该 scope 的最新序号。后续页沿用上次 `through`，每成功应用一页就存下该页最后一个 `seq` 作为新 `after`。当 `more=false` 时清空分页上界，下一次再取新窗口。局部序号可能跳跃，无需把跳号当作丢包。协议的最大 `limit` 为 100 条，响应也受字节上限约束，客户端以 `more` 判断分页结束。

```json
{"cmd_id":"pull-01","op":"sync.pull","scope":"threads/app","after":0,"limit":50}
```

```json
{"cmd_id":"pull-01","ok":true,"result":{"epoch":"<db epoch>","scope":"threads/app","after":0,"through":120,"more":true,"events":[{"seq":25,"kind":"thread.upsert","data":{"thread_id":"<id>","workspace_id":"app","agent":"codex","session_id":"<ACP id>","path":".","title":"调试登录","updated_at":"2026-11-24T14:00:00.000000000Z","archived":false,"history_imported":true}}]}}
```

下一页发 `epoch=<db epoch>, after=25, through=120`。启动、重连与回到前台都应该主动 pull 已选范围。收到 hint 时标记该 scope 为 dirty。每个 scope 同时最多一个分页任务。任务跑完若观察到新 hint，或一段时间内没有流量，再从已存游标追一次。仅凭订阅和 hint 不能判断已追平。

当服务返回 `reset=true`，在一个本地事务里删除这个 scope 的投影、原始事件、未完成分片和游标，再用该响应的 epoch、从 0 拉取。重连时若 `ping` 的 epoch 与已记住的不同，也可以先把旧作用域标记为需要重建。重建时若已验证的服务器返回 `not_found`，清除该 scope 的旧缓存并更新选中状态。不同 epoch 的出站命令必须保持待人工核对态。数据库可能丢失了这些命令的记录，自动改写 epoch 有可能重复执行模型任务或工具操作。

### 事件格式

每个事件有 64 位整数 `seq`、`kind`、`data`。iOS 使用 `Int64`。保留原始事件用于容错，遇到未知 kind 时仍可推进游标。

| kind | 数据 |
| --- | --- |
| `thread.upsert` | 完整 thread 列表对象，运行中带 `active_turn_id`。 |
| `session.setup` | 新会话的 ACP `session/new` 结果，可能包含模式或配置选项。 |
| `acp.history` | 首次打开导入的 ACP `SessionNotification`。可按它的 `update.sessionUpdate` 重建消息和工具卡片。 |
| `turn.started` | `turn_id`、`device_id`、`cmd_id`，用于关联设备上的待发送行。 |
| `message.user` | `turn_id` 和原 ACP `prompt` 数组。将它作为实时用户消息的规范来源。 |
| `acp.update` | `turn_id`、`notification`。将文本增量应用到同一回复，按工具 ID 合并工具状态，按需要展示计划和其他更新。若 Agent 发来用户消息的回显，可用对应的 `message.user` 做展示去重。 |
| `permission.requested` | `permission_id`、`turn_id`、ACP 的 `request`，其中有 `options` 和工具信息。 |
| `permission.resolved` | `permission_id`、`status`，已答复时有 `answer`（`device_id`、`option_id`），过期时为 null。 |
| `turn.finished` | `turn_id`、`status` 和可用时的 `stop_reason`。状态为 `finished`、`cancelled`、`failed` 或 `interrupted`。 |
| `event.fragment` | `id`、原始 `kind`、从 0 开始的 `part`、`last`、标准 Base64 的 `bytes`。 |

原始事件约超过 32 KiB 时会被拆分。分片按序、相邻写入同一个 scope；分页可以从中间切开。客户端把分片按 `(scope,id,part)` 持久化，收到末片且分片号齐全后，拼回 UTF-8 JSON 并应用一次。将分片暂存和游标更新放在同一事务中。收到结尾事件后再结束对应 turn 的 UI 状态。

## 5. Swift 本地库和出站队列

以下是最小本地持久化结构。用 GRDB 或同等 SQLite 封装，为每个已配对 host 和设备建独立数据库。参考实现见 `internal/replica/replica.go`，可配合真实 MQTT 端到端测试核对。

```sql
CREATE TABLE scope (
    key TEXT PRIMARY KEY,
    epoch TEXT NOT NULL DEFAULT '',
    cursor INTEGER NOT NULL DEFAULT 0,
    through INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE event (
    scope TEXT NOT NULL REFERENCES scope(key) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (scope, seq)
);
CREATE TABLE outbox (
    id TEXT PRIMARY KEY,
    epoch TEXT NOT NULL,
    payload BLOB NOT NULL,
    reply BLOB
);
```

启用 SQLite 外键。界面可在此基础上加 thread、message、turn、permission 等投影表，用数据库观察替代全屏网络等待。

1. **应用一页。** 捕获发请求时的 scope、epoch、after、through。收到响应先匹配 `cmd_id` 与 scope。一个写事务内重新读游标，确认请求仍是当前分页。按 `seq` 顺序插入事件，更新投影和分片，再写游标与分页上界。事务失败就原游标重拉。重复或迟到的响应在游标比较时丢弃。界面读取已提交的数据。
2. **离线发消息。** 生成 UUID，用当前已知 epoch 编码出完整命令，作为原始 BLOB 与本地待发送行一起写入。进程重启后重新显示这条待发送消息。未曾配对的设备可以先存草稿，首次取得 epoch 后再生成命令。依赖新 thread ID 的消息等到创建成功后再编码。
3. **重放队列。** 在配对的证书指纹下连接，订阅 reply，确认当前 epoch。按插入顺序发布该 epoch 尚未完成的命令，每个 thread 保持自己的因果顺序。重发同一条时从 BLOB 读取原字节。收到应用结果后持久化 `reply`。回复丢失时继续重发原命令，命令成功和失败都可回显到本地待发送行。
4. **关联本地和服务端。** 收到 `turn.started` 后用 `device_id` 和 `cmd_id` 将待发送行关联到真实 turn。同步到了 `message.user` 后显示一条消息，并保留 outbox 记录直到应用结果到达。审批界面从当前仍 pending 的对象渲染，收到了 `permission.resolved` 就关闭。跨 epoch 的待发送记录由用户核对后决定是否重新发送为新命令。
5. **连接掉线。** 暂停发包，继续读本地缓存。已经运行的 Agent 任务可继续。重连后立即拉取已选 scope，并继续追踪它的完成事件。iOS 从后台恢复时同样做这一步。离线期间没有实时审批提醒。

## 6. 和 TypeScript demo 的功能对照

| TS demo | Go 接入方式 |
| --- | --- |
| `/acp` WebSocket、Bearer token、ACP initialize | 内嵌 MQTT 5、TLS 指纹、Ed25519；客户端使用本文 JSON 协议。 |
| `_johnny/list_directories`、绝对路径选择 | `workspaces.list` + `directories.list`，在管理员配置的工作区内分页浏览。 |
| `session/new`、`session/list` | `thread.create`、`thread.refresh`、`threads/{workspace_id}`。刷新是显式动作，可在前台按需触发。 |
| `session/load` / `session/resume`、中途加入、历史回放 | `thread.open` + 选择 `thread/{thread_id}` 并增量拉取。导入取决于 adapter 的历史重放能力，返回 `history_imported=false` 时能继续对话但旧历史尚未同步。 |
| `session/prompt`、输出流、运行中与完成通知 | `prompt.send` + `turn.started`、`acp.update`、`turn.finished`，两台设备可独立追平。 |
| `session/request_permission`、多客户端审批 | `permission.requested` + `permission.answer`，第一个有效答复写入同步流。 |
| `session/cancel` | `turn.cancel`，需带准确的 `turn_id`。 |
| `session/close`、客户端断线 | 客户端离开 scope 即可。正在运行的任务由服务端管理，重新打开能补齐。 |
| `_johnny/read_project_file` | `file.read`，按 thread 的项目目录读取，按需分页。 |
| `session/fork`、`session/delete`、透传 ACP 配置变更 | 目前提供列表重命名和归档。分叉、删除 Agent 会话和修改 ACP 配置尚未迁移。 |
| `/shell` 多标签 PTY 与抢控制权 | Go 版尚未迁移。现有终端功能仍在 TS demo。 |

两套客户端协议不同，Swift 需要接入 MQTT JSON 和本地同步库才能使用 Go 服务。TS demo 的临时 replay 不包含可直接导入的持久化数据库。Go 通过同一 Agent 账号的 `session/list` 重新发现现有会话，然后在首次打开时尝试导入历史。

## 7. 验收和运维

```sh
go test -buildvcs=false -race ./...
```

MQTT 集成测试需要能监听本地 TCP。测试使用真实 TLS、MQTT 和 SQLite，使用可复现的测试 Agent，覆盖两设备订阅、会话发现和导入、断开并重开客户端数据库、出站重放和大响应分片。上线前用实际运行账号登录 Agent，按相同流程验证 Codex 和 pi 的能力及历史重放，必要时在预发环境固定 adapter 版本。

备份用 SQLite 的在线备份机制，或先停止服务再复制数据目录。保留 `host.pem` 可以延续已配对设备的 TLS 信任。恢复较旧备份、复制成新服务实例或需要主动让设备重建缓存时，为恢复后的数据库轮换 epoch。操作应在服务停止时进行。

```sh
sqlite3 /path/to/johnnybot.db \
  "UPDATE meta SET value=lower(hex(randomblob(16))) WHERE key='epoch';"
```

正常重启沿用 epoch；已运行的 turn 标记为 interrupted，待答复审批过期。同一 epoch 中尚未领取的写命令会继续处理。已领取且没有提交结果的命令持久化为 interrupted。当前服务保留事件日志和命令去重记录，容量规划应包含消息、工具输出及 WAL。初次导入的单个 Agent 历史最多 20,000 条更新和 32 MiB，超过时会报告 `history_too_large`。
