# mDNS 网站测绘 CLI MVP 技术设计

状态：待评审草案  
日期：2026-08-13  
实现时限：30 分钟  
协作方式：1 个协调者 + 3 个并行 Agent

## 1. 结论

半小时内无法稳妥交付一个“完善的网站测绘器”，但可以交付一个边界明确、能编译、能测试、能进行真实网络尝试的 mDNS/DNS-SD MVP。

本期选择方案 B：

1. 向 `224.0.0.251:5353` 发送 IPv4 mDNS 组播查询。
2. 对 CIDR 内每个 IPv4 地址的 UDP `5353` 发起有限并发的单播查询。
3. 关联 PTR、SRV、TXT、A、AAAA 记录。
4. 按用户输入的端口范围过滤 SRV 服务。
5. 输出 IP、端口、主机名、TTL、服务类型和 TXT 深度 Banner。

30 分钟内可以可靠验收的是“解析和 Banner 聚合深度”，即使用固定 DNS 记录数据集证明输出达到 QNAP 示例深度。真实局域网发现率不能作为硬性通过条件，因为部分设备不响应单播 mDNS，组播也可能被 VLAN、VPN、防火墙或无线 AP 隔离。

## 2. 目标与非目标

### 2.1 本期目标

CLI 示例：

```bash
mdnscan \
  --cidr 192.168.1.0/24 \
  --ports 9,445,548,5000 \
  --timeout 3s \
  --interface en0
```

设备实际广播相应记录时，程序能够输出：

- IPv4、IPv6 地址
- 服务端口和 TCP/UDP 协议
- 服务类型和实例名称
- Hostname
- TTL
- TXT 中的 `path`、`model`、`displayModel`、`fwVer`、`fwBuildNum`、`accessType`、`accessPort` 等属性
- PTR 服务类型列表

### 2.2 明确不做

- 不连接 SRV 公布的业务端口。
- 不实现 HTTP、TLS、SMB、AFP 或厂商私有协议的主动探针。
- 不保证跨路由器、VLAN、VPN、云网络发现。
- 不枚举 IPv6 网段，也不发送 IPv6 组播；但解析并输出响应中的 AAAA 记录。
- 不做 JSON、数据库、PCAP、持续监听、缓存冲突处理和自动重试。
- 不将“真实网络没有发现设备”视为程序失败。

因此这里的“端口范围”表示：过滤 mDNS SRV 记录中公布的服务端口，而不是 TCP/UDP 通用端口扫描。

## 3. 可行性再评估

| 内容 | 30 分钟可行性 | 决策 |
|---|---:|---|
| CLI 参数、CIDR、端口范围解析 | 高 | P0 必须完成 |
| PTR/SRV/TXT/A/AAAA 关联 | 高 | P0 必须完成 |
| 示例级 Banner 与固定数据集测试 | 高 | P0 必须完成 |
| IPv4 组播查询 | 中 | P1 尽力完成 |
| CIDR 单播 UDP 5353 查询 | 中 | P1 尽力完成 |
| 多轮服务类型跟进查询 | 中低 | 内置常用类型作为降级 |
| 各操作系统下稳定的组播接口选择 | 低 | 只保证 macOS/Linux 常规环境尝试 |
| 主动探测业务端口并识别应用协议 | 极低 | P2 延后 |

优先级定义：

- P0：没有它就不能证明需求核心能力。
- P1：真实扫描路径，允许受网络环境影响，但必须有清晰错误处理。
- P2：超出半小时 MVP，不进入本次开发。

若时间不足，必须优先保证 P0 全绿，再保证至少一条真实网络查询路径可运行。不能为了展示“扫到了设备”而牺牲确定性的解析测试。

## 4. 技术方案比较

### 4.1 方案一：纯标准库实现 DNS 报文

自行处理 DNS 编码、压缩名称、RR 解码和异常报文。

优点：无第三方依赖。  
缺点：30 分钟内压缩域名解析和边界处理风险过高，容易出现“简单响应可用，真实设备响应失败”。

### 4.2 方案二：`github.com/miekg/dns` + 自定义 UDP 传输

使用成熟库构造和解析 DNS 报文，自行实现组播/单播调度、记录聚合和输出。

优点：能保留完整 PTR、SRV、TXT、A、AAAA 信息，也能控制指定 IP 的单播查询。  
缺点：仍需处理 socket 生命周期、超时和并发。

本项目选择此方案。

### 4.3 方案三：`github.com/hashicorp/mdns`

直接使用高层服务发现接口。

优点：标准组播服务发现实现更快。  
缺点：不适合逐 IP 单播查询，原始记录和响应来源信息也不够贴合本项目输出模型。

## 5. CLI 契约

```text
Usage:
  mdnscan --cidr CIDR --ports PORTS [flags]

Required:
  --cidr       IPv4 CIDR，例如 192.168.1.0/24
  --ports      端口及范围，例如 9,445,5000-5010

Optional:
  --timeout    每个发现阶段的接收窗口，默认 3s
  --interface  网卡名称；为空时使用系统路由选择
  --workers    单播查询并发，默认 32，最大 256
  --max-hosts  网段地址数上限，默认 4096
```

规则：

- CIDR 地址数超过 `--max-hosts` 时，在发送任何数据包前拒绝执行。
- 端口合法范围为 `1..65535`，支持单值、逗号和闭区间组合。
- 网络地址和广播地址也进入查询列表，避免错误假设点对点或非传统 IPv4 网络语义。
- 没发现资产时退出码为 `0`，并向 stderr 输出说明。
- 参数错误退出码为 `2`；无法建立必要 socket 时退出码为 `1`。

## 6. 总体架构

```text
cmd/mdnscan
    |
    v
参数校验 ---> CIDR + PortSet
    |
    v
Discovery
    |-- 组播查询 ----> 224.0.0.251:5353
    |-- 单播工作池 --> CIDR 内各 IP:5353
    |
    v
[]QueryResult { SourceIP, []dns.RR }
    |
    v
Correlator
    PTR  -> 服务类型/实例
    SRV  -> Hostname/Port
    TXT  -> Banner 属性
    A/AAAA -> 地址
    |
    v
CIDR/端口过滤 ---> 稳定文本输出
```

目录规划：

```text
cmd/mdnscan/main.go
internal/model/asset.go
internal/target/cidr.go
internal/target/ports.go
internal/discovery/query.go
internal/discovery/multicast.go
internal/discovery/unicast.go
internal/correlate/correlate.go
internal/render/text.go
internal/testfixture/qnap.go
```

## 7. 冻结的公共契约

协调者必须先创建公共类型和接口，再允许并行 Agent 修改业务文件。其他 Agent 不得自行改变这些签名。

```go
package model

type QueryResult struct {
    Source net.IP
    RRs    []dns.RR
}

type Service struct {
    Instance string
    Type     string
    Protocol string
    Port     uint16
    Hostname string
    IPv4     []net.IP
    IPv6     []net.IP
    TTL      uint32
    TXT      []string
}

type Asset struct {
    Hostname string
    IPv4     []net.IP
    IPv6     []net.IP
    Services []Service
    PTR      []string
}
```

```go
package target

func ParseCIDR(raw string, maxHosts int) (*net.IPNet, []net.IP, error)

type PortSet interface {
    Contains(port uint16) bool
}

func ParsePorts(raw string) (PortSet, error)
```

```go
package discovery

type Config struct {
    CIDR      *net.IPNet
    Hosts     []net.IP
    Interface *net.Interface
    Timeout   time.Duration
    Workers   int
}

func Discover(ctx context.Context, cfg Config) ([]model.QueryResult, error)
```

```go
package correlate

func Build(
    results []model.QueryResult,
    cidr *net.IPNet,
    ports interface{ Contains(uint16) bool },
) []model.Asset
```

```go
package render

func Text(w io.Writer, assets []model.Asset) error
```

`QueryResult` 必须保留每个响应报文的来源 IP。这样即使响应没有 A 记录，关联器仍能判断单播响应是否来自目标 CIDR；不能把所有 RR 扁平化后丢失来源。

## 8. 发现流程

### 8.1 组播阶段

1. 创建临时 UDP4 socket，避免强制占用本机 `5353`。
2. 构造 ID 为 `0` 的 mDNS PTR 查询，并设置 QU 位请求单播响应。
3. 查询 `_services._dns-sd._udp.local.`。
4. 在超时窗口内收集所有响应报文及来源 IP。
5. 对发现的服务类型发送后续 PTR 查询。

### 8.2 CIDR 单播阶段

1. 枚举经过 `--max-hosts` 限制的 IPv4 地址。
2. 使用固定大小工作池向每个 `IP:5353` 发送 mDNS 查询。
3. 每个目标先查询 `_services._dns-sd._udp.local.`。
4. 对响应中出现的服务类型继续查询。
5. 单 IP 超时、拒绝或无响应均为非致命结果。

### 8.3 服务类型降级

部分设备不响应 `_services._dns-sd._udp.local.` 元查询。若没有发现服务类型，允许查询以下内置列表：

```text
_workstation._tcp.local.
_http._tcp.local.
_smb._tcp.local.
_qdiscover._tcp.local.
_device-info._tcp.local.
_afpovertcp._tcp.local.
```

内置列表只作为降级，不代表完整服务字典。

### 8.4 去重

记录去重键：

```text
来源 IP + RR 类型 + 小写 Owner Name + 规范化 RDATA
```

相同设备通过组播和单播返回相同记录时，关联结果还需要按服务实例、Hostname 和端口二次去重。

## 9. DNS-SD 关联和 Banner 规则

关联图：

```text
服务类型 --PTR--> 服务实例
服务实例 --SRV--> 目标 Hostname + 端口
服务实例 --TXT--> 属性列表
目标 Hostname --A/AAAA--> IPv4/IPv6
```

只有存在 SRV 的服务才进入最终 `services`。服务还必须满足：

1. SRV 端口在用户指定的 PortSet 中。
2. 至少一个 A 地址位于目标 CIDR，或者该服务记录来自 CIDR 内的单播响应源。

字段规则：

- `Name`：从实例全名中移除服务类型后缀。
- `Hostname`：移除末尾的点。
- `Protocol`：从服务类型的 `_tcp` 或 `_udp` 提取。
- `TTL`：取相关 PTR、SRV、TXT、A、AAAA 中最小的非零 TTL。
- `TXT`：保持原始字符串顺序，使用逗号连接；字段内第一个 `=` 分隔 key/value。
- IP、PTR 和服务列表均去重并排序，保证测试输出稳定。

目标输出：

```text
services:
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.20
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
answers:
PTR:
_qdiscover._tcp.local
```

## 10. 错误处理和流量限制

- 拒绝错误 CIDR、空端口、倒序区间、越界端口和非法并发数。
- 单个错误 DNS 报文只丢弃该报文，不中断整个扫描。
- 单 IP 超时和 ICMP 拒绝不向上返回致命错误。
- 只输出成功关联到 SRV 的服务，避免用孤立 TXT 或 PTR 制造假资产。
- UDP 接收缓冲区最大 64 KiB。
- 所有 socket 和 worker 受同一个 context 控制。
- MVP 不重试，避免大网段流量倍增。
- 默认最大 4096 个目标、32 个 worker，防止误输入大网段造成无界扫描。

## 11. 测试和验收

### 11.1 P0 自动化验收

1. 端口解析支持 `9,445,5000-5010`，拒绝 `0`、`65536` 和 `5000-4000`。
2. CIDR 解析拒绝 IPv6 和超过 `--max-hosts` 的网段。
3. QNAP fixture 同时包含 PTR、SRV、TXT、A、AAAA。
4. 关联和渲染结果至少包含：

```text
5000/tcp qdiscover:
Name=slw-nas
IPv4=192.168.1.20
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https
accessPort=86
model=TS-X64
displayModel=TS-464C
fwVer=5.2.9
fwBuildNum=20260214
_qdiscover._tcp.local
```

5. 端口范围不包含 `5000` 时，不输出该服务。
6. 重复 RR 不产生重复服务或重复 IP。

### 11.2 P1 网络验收

```bash
go run ./cmd/mdnscan \
  --cidr 192.168.1.0/24 \
  --ports 1-65535 \
  --timeout 3s \
  --interface en0
```

网络验收通过条件：程序能建立查询、按时退出，发现响应时能输出完整关联结果。零结果不作为失败，因为测试网络可能没有 mDNS 响应者。

最终工程命令：

```bash
gofmt -w cmd internal
go test ./...
go vet ./...
go build ./cmd/mdnscan
```

## 12. 30 分钟并行任务拆分

并行阶段只有 3 个 Agent 修改业务文件；协调者负责公共契约、依赖和最终接线。所有 Agent 必须遵守文件所有权，不能修改他人文件。

### 0-4 分钟：协调者启动

负责：

- 初始化 Git 和 Go module。
- 添加固定版本的 `github.com/miekg/dns`。
- 创建 `internal/model/asset.go`。
- 冻结第 7 节函数签名。
- 创建最小 `cmd/mdnscan/main.go`，但不完成业务接线。
- 提交 bootstrap，让全部 Agent 从同一契约开始。

### 4-19 分钟：三个 Agent 并行

#### Agent A：目标解析

独占文件：

```text
internal/target/cidr.go
internal/target/cidr_test.go
internal/target/ports.go
internal/target/ports_test.go
```

交付：CIDR 校验和枚举、地址数限制、端口表达式解析、`Contains` 查询及测试。

#### Agent B：网络发现

独占文件：

```text
internal/discovery/query.go
internal/discovery/multicast.go
internal/discovery/unicast.go
internal/discovery/query_test.go
```

交付：mDNS 报文构造、组播阶段、有限并发单播阶段、超时取消、RR 收集和去重。测试必须通过注入传输函数或本地 UDP socket 完成，不依赖真实 LAN。

#### Agent C：关联与输出

独占文件：

```text
internal/correlate/correlate.go
internal/correlate/correlate_test.go
internal/render/text.go
internal/render/text_test.go
internal/testfixture/qnap.go
```

交付：DNS-SD 图关联、CIDR/端口过滤、稳定文本渲染和达到示例深度的 QNAP fixture 测试。

### 19-30 分钟：协调者集成

- 检查三个 Agent 是否修改越界文件。
- 将 `main.go` 接到 target、discovery、correlate 和 render。
- 统一 `gofmt`。
- 依次运行 `go test ./...`、`go vet ./...`、`go build ./cmd/mdnscan`。
- 只修编译、契约和 P0 验收阻塞问题。
- 有已授权的网卡和 CIDR 时才运行真实网络 smoke test。

### Agent 回报格式

每个 Agent 必须返回：

1. 修改文件列表。
2. 执行的测试命令和准确结果。
3. 未完成项或集成假设。
4. 确认未修改其他 Agent 或协调者所有的文件。

如果多个 Agent 共享一个工作目录，只有协调者能修改 `go.mod`、`go.sum`、`internal/model` 和 `cmd/mdnscan/main.go`。使用独立 worktree 更稳妥，但半小时时限下不强制。

## 13. 风险与降级顺序

| 风险 | 影响 | 降级措施 |
|---|---|---|
| DNS 依赖无法下载 | 无法构建 | 启动阶段立即检查；不要临时手写 DNS 解码 |
| macOS/Linux socket 行为差异 | 组播路径不稳定 | 保留可测试的传输边界，明确输出 socket 错误 |
| 设备不响应单播 mDNS | CIDR 阶段结果少 | 以组播为主，单播标记为 best effort |
| 元查询不返回服务类型 | 无法继续关联 | 查询 6 个内置常见服务类型 |
| Agent 修改公共契约 | 集成时编译冲突 | 第 4 分钟前冻结契约，只有协调者能改 |
| 时间耗尽 | 网络路径不完整 | 优先保住 P0：解析、关联、Banner、fixture、构建 |

## 14. 完成定义

同时满足以下条件才算 MVP 完成：

- `go test ./...` 通过。
- `go vet ./...` 通过。
- `go build ./cmd/mdnscan` 通过。
- CLI 能拒绝非法 CIDR、超大网段和非法端口表达式。
- fixture 能输出 IP、端口、Name、Hostname、TTL、IPv6、PTR 和 QNAP 示例级 TXT Banner。
- SRV 端口不在用户范围内时不输出。
- 存在 IPv4 组播和 CIDR 单播查询代码，并且遵守 timeout/context。
- CLI help 明确说明 mDNS 的本地网络限制和单播查询的 best-effort 语义。

其他功能全部进入后续版本，不在本次半小时交付中追加。
