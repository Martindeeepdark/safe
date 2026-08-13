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
