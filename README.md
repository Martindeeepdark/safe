# mdnscan

`mdnscan` is a small Go CLI for authorized mDNS/DNS-SD asset discovery. It combines local IPv4 multicast discovery with best-effort UDP `5353` queries to each address in an IPv4 CIDR, then correlates PTR, SRV, TXT, A, and AAAA records into service banners.

## Build

```bash
go build -o mdnscan ./cmd/mdnscan
```

## Usage

```bash
./mdnscan \
  --cidr 192.168.1.0/24 \
  --ports 9,445,548,5000 \
  --timeout 3s \
  --interface en0
```

Important flags:

```text
--cidr       IPv4 network to include and query
--ports      comma-separated SRV ports and inclusive ranges
--timeout    receive window for each discovery phase
--interface  interface used for multicast queries
--workers    concurrent per-IP UDP queries, default 32
--max-hosts  CIDR address limit, default 4096
```

The port expression filters ports advertised by DNS-SD SRV records. The program does not connect to HTTP, SMB, AFP, or other application ports.

## Output

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

## Network limits

mDNS multicast is normally limited to the local link. Routers, VLANs, VPNs, firewalls, and wireless isolation can prevent responses. Per-IP unicast mDNS queries are best effort because many devices only answer multicast queries. A scan with no results does not prove that the target addresses expose no mDNS services.

Run this tool only against networks and devices you are authorized to inspect.
