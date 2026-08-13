# mDNS Asset CLI Implementation Plan

> **For agentic workers:** This is a 30-minute implementation-first plan. The user explicitly waived TDD and high coverage. Implement owned files first, then add only critical regression tests for parsing, QNAP banner correlation, and build safety.

**Goal:** Build a timeboxed Go CLI that discovers mDNS/DNS-SD assets with IPv4 multicast plus best-effort CIDR unicast and renders PTR/SRV/TXT/A/AAAA data at the required QNAP banner depth.

**Architecture:** The coordinator owns module setup, shared types, CLI integration, and final verification. Three parallel workers own target parsing, network discovery, and record correlation/rendering without overlapping files. `github.com/miekg/dns` handles DNS wire encoding and decoding; project code handles sockets, correlation, filtering, and deterministic output.

**Tech Stack:** Go 1.24, standard `flag`/`net`/`context` packages, `github.com/miekg/dns`, minimal Go `testing` regression coverage.

---

## File Map

```text
go.mod                              module and DNS dependency; coordinator only
go.sum                              dependency checksums; coordinator only
cmd/mdnscan/main.go                 flags, validation, pipeline, exit codes; coordinator only
internal/model/asset.go             frozen shared records and asset types; coordinator only
internal/target/cidr.go             IPv4 CIDR validation/enumeration; Agent A
internal/target/cidr_test.go        CIDR behavior; Agent A
internal/target/ports.go            port expression parser; Agent A
internal/target/ports_test.go       port behavior; Agent A
internal/discovery/query.go         discovery orchestration and RR helpers; Agent B
internal/discovery/multicast.go     multicast UDP query phase; Agent B
internal/discovery/unicast.go       bounded unicast worker pool; Agent B
internal/discovery/query_test.go    deterministic query/dedup tests; Agent B
internal/correlate/correlate.go     PTR/SRV/TXT/A/AAAA graph; Agent C
internal/correlate/correlate_test.go correlation/filter tests; Agent C
internal/render/text.go             stable text banner; Agent C
internal/render/text_test.go        example-depth output test; Agent C
internal/testfixture/qnap.go        deterministic QNAP-like RR set; Agent C
README.md                           usage and protocol limits; coordinator only
```

## Task 1: Coordinator Bootstrap

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `internal/model/asset.go`
- Create: `cmd/mdnscan/main.go`

- [ ] **Step 1: Initialize the module and dependency**

Run:

```bash
go mod init mdnscan
go get github.com/miekg/dns@v1.1.68
```

Expected: `go.mod` contains module `mdnscan` and a fixed `github.com/miekg/dns` version.

- [ ] **Step 2: Create frozen shared types**

Create `internal/model/asset.go`:

```go
package model

import (
    "net"

    "github.com/miekg/dns"
)

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

- [ ] **Step 3: Create a compiling CLI placeholder**

Create `cmd/mdnscan/main.go`:

```go
package main

func main() {}
```

- [ ] **Step 4: Verify bootstrap**

Run:

```bash
gofmt -w internal/model/asset.go cmd/mdnscan/main.go
go test ./...
```

Expected: PASS with no test files.

## Task 2: Agent A - Target Parsing

**Files:**
- Create: `internal/target/cidr.go`
- Create: `internal/target/cidr_test.go`
- Create: `internal/target/ports.go`
- Create: `internal/target/ports_test.go`

- [ ] **Step 1: Implement bounded IPv4 CIDR parsing**

Tests must cover:

```go
func TestParseCIDRIPv4(t *testing.T) {
    network, hosts, err := ParseCIDR("192.168.1.0/30", 4)
    if err != nil {
        t.Fatal(err)
    }
    if network.String() != "192.168.1.0/30" {
        t.Fatalf("network = %s", network)
    }
    got := []string{hosts[0].String(), hosts[1].String(), hosts[2].String(), hosts[3].String()}
    want := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("hosts = %v, want %v", got, want)
    }
}

func TestParseCIDRRejectsIPv6(t *testing.T) {
    if _, _, err := ParseCIDR("fe80::/64", 4096); err == nil {
        t.Fatal("expected IPv6 rejection")
    }
}

func TestParseCIDRHonorsLimit(t *testing.T) {
    if _, _, err := ParseCIDR("10.0.0.0/24", 100); err == nil {
        t.Fatal("expected host limit error")
    }
}
```

- [ ] **Step 2: Add the three critical CIDR regression tests**

Run: `go test ./internal/target -run TestParseCIDR -v`  
Expected: PASS.

- [ ] **Step 3: Implement port parsing**

Implement:

```go
func ParseCIDR(raw string, maxHosts int) (*net.IPNet, []net.IP, error)
```

Required behavior:

- reject `maxHosts <= 0`;
- call `net.ParseCIDR`;
- reject `ip.To4() == nil`;
- calculate count from the IPv4 mask before allocating;
- reject counts above `maxHosts`;
- enumerate every address including network and broadcast;
- copy each `net.IP` before incrementing it.

- [ ] **Step 4: Add compact table-driven port regression tests**

Tests must assert:

```go
set, err := ParsePorts("9,445,5000-5002")
// Contains 9, 445, 5000, 5001, 5002; does not contain 10.
```

Table-driven invalid cases:

```go
[]string{"", "0", "65536", "5000-4000", "80-", "abc", "80,,443"}
```

- [ ] **Step 5: Run target package tests**

Run: `go test ./internal/target -run TestParsePorts -v`  
Expected: PASS.

- [ ] **Step 6: Implement PortSet**

Expose exactly:

```go
type PortSet interface {
    Contains(port uint16) bool
}

func ParsePorts(raw string) (PortSet, error)
```

Use a private `[65536]bool`-backed type or `map[uint16]struct{}`. Trim whitespace around list items, but reject empty items. Ranges are inclusive.

- [ ] **Step 7: Verify Agent A package**

Run:

```bash
gofmt -w internal/target
go test ./internal/target -v
```

Expected: PASS.

## Task 3: Agent B - Network Discovery

**Files:**
- Create: `internal/discovery/query.go`
- Create: `internal/discovery/multicast.go`
- Create: `internal/discovery/unicast.go`
- Create: `internal/discovery/query_test.go`

- [ ] **Step 1: Write failing query construction tests**

Tests must verify that:

```go
msg := newPTRQuery("_services._dns-sd._udp.local.")
```

produces ID `0`, one PTR question, class `INET`, and the unicast-response bit in QCLASS.

- [ ] **Step 2: Write failing RR extraction and dedup tests**

Create a `dns.Msg` with records split across `Answer`, `Ns`, and `Extra`. Assert `messageRRs` returns all of them. Pass duplicate `model.QueryResult` values to `dedupeResults` and assert duplicates from the same source collapse while identical RRs from different sources remain attributable.

- [ ] **Step 3: Run tests and confirm failure**

Run: `go test ./internal/discovery -v`  
Expected: FAIL because query helpers do not exist.

- [ ] **Step 4: Implement discovery API and helpers**

Expose exactly:

```go
type Config struct {
    CIDR      *net.IPNet
    Hosts     []net.IP
    Interface *net.Interface
    Timeout   time.Duration
    Workers   int
}

func Discover(ctx context.Context, cfg Config) ([]model.QueryResult, error)
```

Private helpers:

```go
func newPTRQuery(name string) *dns.Msg
func messageRRs(msg *dns.Msg) []dns.RR
func dedupeResults(results []model.QueryResult) []model.QueryResult
func serviceTypes(results []model.QueryResult) []string
```

`newPTRQuery` must normalize the name with `dns.Fqdn`, set ID `0`, and request a unicast response without changing the RR type.

- [ ] **Step 5: Implement one UDP exchange primitive**

Implement a private helper that:

- creates `net.ListenUDP("udp4", &net.UDPAddr{IP: bindIP, Port: 0})`;
- packs the DNS message using `msg.Pack()`;
- writes to the destination UDP address;
- sets short read deadlines bounded by the phase context;
- decodes all received messages with `dns.Msg.Unpack`;
- returns `model.QueryResult{Source: remote.IP, RRs: messageRRs(msg)}`;
- treats deadline expiration as successful completion;
- returns context cancellation immediately.

- [ ] **Step 6: Implement multicast phase**

Send `_services._dns-sd._udp.local.` to `224.0.0.251:5353`, collect responses, then query discovered service types. When the meta-query returns no service type, query exactly:

```go
var fallbackServices = []string{
    "_workstation._tcp.local.",
    "_http._tcp.local.",
    "_smb._tcp.local.",
    "_qdiscover._tcp.local.",
    "_device-info._tcp.local.",
    "_afpovertcp._tcp.local.",
}
```

Use the configured interface's first IPv4 address as the bind/source address when supplied.

- [ ] **Step 7: Implement bounded unicast phase**

Use `cfg.Workers` goroutines and a jobs channel over `cfg.Hosts`. Each target receives the meta-query; responding service types receive follow-up queries. Per-host timeout/refusal is non-fatal. Values outside `1..256` produce a configuration error.

- [ ] **Step 8: Verify Agent B package**

Run:

```bash
gofmt -w internal/discovery
go test ./internal/discovery -v
```

Expected: PASS without requiring a live LAN.

## Task 4: Agent C - Correlation, Fixture, and Rendering

**Files:**
- Create: `internal/testfixture/qnap.go`
- Create: `internal/correlate/correlate.go`
- Create: `internal/correlate/correlate_test.go`
- Create: `internal/render/text.go`
- Create: `internal/render/text_test.go`

- [ ] **Step 1: Build deterministic QNAP fixture**

Expose:

```go
func QNAP() []model.QueryResult
```

Use source `192.168.1.20` and `dns.NewRR` to create at minimum:

```text
_services._dns-sd._udp.local. 10 IN PTR _qdiscover._tcp.local.
_qdiscover._tcp.local. 10 IN PTR slw-nas._qdiscover._tcp.local.
slw-nas._qdiscover._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local.
slw-nas._qdiscover._tcp.local. 10 IN TXT "accessType=https" "accessPort=86" "model=TS-X64" "displayModel=TS-464C" "fwVer=5.2.9" "fwBuildNum=20260214"
slw-nas.local. 10 IN A 192.168.1.20
slw-nas.local. 10 IN AAAA fe80::265e:beff:fe69:a313
```

- [ ] **Step 2: Write failing correlation tests**

Tests call:

```go
assets := Build(testfixture.QNAP(), cidr, ports)
```

Assert one service with port `5000`, protocol `tcp`, type `_qdiscover._tcp.local`, name `slw-nas`, hostname `slw-nas.local`, TTL `10`, both IP versions, ordered TXT strings, and PTR summary.

Add tests proving:

- a PortSet excluding `5000` emits no service;
- duplicate RRs do not duplicate services or IPs;
- a response source inside the CIDR permits a service when no A RR is present.

- [ ] **Step 3: Run correlation tests and confirm failure**

Run: `go test ./internal/correlate -v`  
Expected: FAIL because `Build` does not exist.

- [ ] **Step 4: Implement DNS-SD graph correlation**

Expose exactly:

```go
func Build(
    results []model.QueryResult,
    cidr *net.IPNet,
    ports interface{ Contains(uint16) bool },
) []model.Asset
```

Implementation rules:

- normalize match keys with lowercased FQDNs;
- collect service-type PTRs separately from service-instance PTRs;
- index SRV/TXT by instance and A/AAAA by hostname;
- derive service type from the PTR owner, not by guessing from the instance string;
- include only SRV ports accepted by `ports`;
- require an in-CIDR A record or an in-CIDR response source associated with the record set;
- compute the minimum non-zero TTL across linked records;
- dedupe IPs, PTR values, and services;
- sort assets and services deterministically.

- [ ] **Step 5: Write failing renderer test**

Render the QNAP asset into `bytes.Buffer` and assert output contains:

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

- [ ] **Step 6: Implement stable text rendering**

Expose:

```go
func Text(w io.Writer, assets []model.Asset) error
```

Render all services below one `services:` header and all unique PTR types below `answers:\nPTR:`. The heading label is the first DNS-SD service label without `_`, for example `qdiscover`. Join multiple IP values with commas and TXT strings with commas.

- [ ] **Step 7: Verify Agent C packages**

Run:

```bash
gofmt -w internal/testfixture internal/correlate internal/render
go test ./internal/correlate ./internal/render -v
```

Expected: PASS.

## Task 5: Coordinator Integration

**Files:**
- Modify: `cmd/mdnscan/main.go`
- Create: `README.md`

- [ ] **Step 1: Replace placeholder with CLI pipeline**

`main` delegates to `run(args, stdout, stderr) int` so exit behavior is testable. Required flow:

```go
network, hosts, err := target.ParseCIDR(cidrFlag, maxHosts)
ports, err := target.ParsePorts(portsFlag)
iface, err := net.InterfaceByName(interfaceFlag) // only when non-empty
results, err := discovery.Discover(ctx, discovery.Config{
    CIDR: network, Hosts: hosts, Interface: iface,
    Timeout: timeoutFlag, Workers: workersFlag,
})
assets := correlate.Build(results, network, ports)
err = render.Text(stdout, assets)
```

Use `flag.NewFlagSet` with `ContinueOnError`. Parameter errors return `2`; discovery/render fatal errors return `1`; success and zero assets return `0`.

- [ ] **Step 2: Add CLI testable validation**

Create `cmd/mdnscan/main_test.go` owned by the coordinator. Assert missing `--cidr`, missing `--ports`, invalid worker count, and invalid interface return non-zero without starting discovery. Keep network execution out of CLI unit tests.

- [ ] **Step 3: Document use and limits**

Create `README.md` containing:

- build command: `go build -o mdnscan ./cmd/mdnscan`;
- example invocation;
- output example;
- explanation that ports filter SRV records instead of connecting to application ports;
- authorization warning;
- local-network and best-effort unicast limitations.

- [ ] **Step 4: Format and run full verification**

Run sequentially:

```bash
gofmt -w cmd internal
go test ./...
go vet ./...
go build ./cmd/mdnscan
```

Expected: all commands exit `0`.

- [ ] **Step 5: Run safe CLI checks**

Run:

```bash
go run ./cmd/mdnscan --cidr invalid --ports 80
go run ./cmd/mdnscan --cidr 127.0.0.1/32 --ports 5000 --timeout 100ms --workers 1
```

Expected: first command exits with parameter error; second exits within a short bounded interval without panic, whether or not it finds an asset.

## Task 6: Review Gate

- [ ] **Step 1: Scope review**

Verify no active TCP/HTTP/TLS/SMB probing was added and no JSON/database persistence was introduced.

- [ ] **Step 2: Concurrency review**

Verify worker count is bounded, every goroutine terminates on context cancellation, sockets are closed, and no result channel can block after cancellation.

- [ ] **Step 3: Protocol/output review**

Verify PTR/SRV/TXT/A/AAAA records from Answer, Authority, and Additional sections are included; result-source IP is retained; SRV ports are filtered; output reaches the fixture depth.

- [ ] **Step 4: Final test replay**

Run:

```bash
go test -count=1 ./...
go vet ./...
go build ./cmd/mdnscan
```

Expected: all commands exit `0` with uncached tests.
