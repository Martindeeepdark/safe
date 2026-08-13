package model

import (
	"net"

	"github.com/miekg/dns"
)

// QueryResult preserves the source IP of each DNS response so the
// correlator can decide whether a unicast responder sits inside the
// requested CIDR even when the packet carries no A record.
type QueryResult struct {
	Source net.IP
	RRs    []dns.RR
}

// Service is one DNS-SD service emitted after PTR/SRV/TXT/A/AAAA
// correlation. The TXT slice preserves received string order for the
// rendered banner.
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

// Asset groups every service that resolved to the same hostname.
// PTR holds the unique discovered service-type names for the answer block.
type Asset struct {
	Hostname string
	IPv4     []net.IP
	IPv6     []net.IP
	Services []Service
	PTR      []string
}
