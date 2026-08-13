package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"mdnscan/internal/model"
)

const (
	mdnsPort    = 5353
	metaService = "_services._dns-sd._udp.local."
	maxWorkers  = 256
)

var fallbackServices = []string{
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_smb._tcp.local.",
	"_qdiscover._tcp.local.",
	"_device-info._tcp.local.",
	"_afpovertcp._tcp.local.",
}

type Config struct {
	CIDR      *net.IPNet
	Hosts     []net.IP
	Interface *net.Interface
	Timeout   time.Duration
	Workers   int
}

func Discover(ctx context.Context, cfg Config) ([]model.QueryResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	hosts := cfg.Hosts
	if len(hosts) == 0 {
		hosts = hostsFromCIDR(cfg.CIDR)
	}

	type outcome struct {
		results []model.QueryResult
		err     error
	}
	outcomes := make(chan outcome, 2)

	go func() {
		results, err := discoverMulticast(ctx, cfg)
		outcomes <- outcome{results: results, err: err}
	}()
	go func() {
		results, err := discoverUnicast(ctx, cfg, hosts)
		outcomes <- outcome{results: results, err: err}
	}()

	var (
		allResults []model.QueryResult
		errs       []error
	)
	for range 2 {
		result := <-outcomes
		allResults = append(allResults, result.results...)
		if result.err != nil {
			errs = append(errs, result.err)
		}
	}

	if err := ctx.Err(); err != nil {
		return mergeResults(allResults), err
	}
	return mergeResults(allResults), errors.Join(errs...)
}

func validateConfig(cfg Config) error {
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than zero")
	}
	if cfg.Workers <= 0 {
		return fmt.Errorf("workers must be between 1 and %d", maxWorkers)
	}
	if cfg.Workers > maxWorkers {
		return fmt.Errorf("workers must be between 1 and %d", maxWorkers)
	}
	return nil
}

func newPTRQuery(name string) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               0,
			RecursionDesired: false,
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(name),
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET | 1<<15, // QU: request a unicast response.
		}},
	}
}

func exchangeQueries(
	ctx context.Context,
	conn *net.UDPConn,
	destination *net.UDPAddr,
	names []string,
	window time.Duration,
	expectedSource net.IP,
) ([]model.QueryResult, error) {
	if window <= 0 {
		return nil, nil
	}

	for _, name := range uniqueNames(names) {
		wire, err := newPTRQuery(name).Pack()
		if err != nil {
			return nil, fmt.Errorf("pack PTR query %q: %w", name, err)
		}
		if _, err := conn.WriteToUDP(wire, destination); err != nil {
			return nil, fmt.Errorf("send PTR query %q to %s: %w", name, destination, err)
		}
	}

	deadline := time.Now().Add(window)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	var results []model.QueryResult
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		now := time.Now()
		if !now.Before(deadline) {
			return results, nil
		}

		readDeadline := deadline
		if pollDeadline := now.Add(100 * time.Millisecond); pollDeadline.Before(readDeadline) {
			readDeadline = pollDeadline
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return results, fmt.Errorf("set UDP read deadline: %w", err)
		}

		count, source, err := conn.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return results, fmt.Errorf("read mDNS response: %w", err)
		}
		if expectedSource != nil && !source.IP.Equal(expectedSource) {
			continue
		}

		var response dns.Msg
		if err := response.Unpack(buffer[:count]); err != nil {
			continue
		}
		rrs := extractRRs(&response)
		if len(rrs) == 0 {
			continue
		}
		results = append(results, model.QueryResult{
			Source: cloneIP(source.IP),
			RRs:    rrs,
		})
	}
}

func extractRRs(message *dns.Msg) []dns.RR {
	if message == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var records []dns.RR
	sections := [][]dns.RR{message.Answer, message.Ns, message.Extra}
	for _, section := range sections {
		for _, rr := range section {
			if !supportedRR(rr) {
				continue
			}
			key := rrKey(rr)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			records = append(records, rr)
		}
	}
	return records
}

func supportedRR(rr dns.RR) bool {
	switch rr.(type) {
	case *dns.PTR, *dns.SRV, *dns.TXT, *dns.A, *dns.AAAA:
		return true
	default:
		return false
	}
}

func rrKey(rr dns.RR) string {
	header := rr.Header()
	prefix := fmt.Sprintf("%d|%d|%s|", header.Rrtype, header.Class&0x7fff, strings.ToLower(dns.Fqdn(header.Name)))
	switch record := rr.(type) {
	case *dns.PTR:
		return prefix + strings.ToLower(dns.Fqdn(record.Ptr))
	case *dns.SRV:
		return fmt.Sprintf("%s%d|%d|%d|%s", prefix, record.Priority, record.Weight, record.Port, strings.ToLower(dns.Fqdn(record.Target)))
	case *dns.TXT:
		return prefix + strings.Join(record.Txt, "\x00")
	case *dns.A:
		return prefix + record.A.String()
	case *dns.AAAA:
		return prefix + record.AAAA.String()
	default:
		return strings.ToLower(rr.String())
	}
}

func serviceTypes(results []model.QueryResult) []string {
	seen := make(map[string]string)
	for _, result := range results {
		for _, rr := range result.RRs {
			ptr, ok := rr.(*dns.PTR)
			if !ok || !strings.EqualFold(dns.Fqdn(ptr.Hdr.Name), metaService) {
				continue
			}
			name := dns.Fqdn(ptr.Ptr)
			seen[strings.ToLower(name)] = name
		}
	}

	types := make([]string, 0, len(seen))
	for _, name := range seen {
		types = append(types, name)
	}
	sort.Slice(types, func(i, j int) bool {
		return strings.ToLower(types[i]) < strings.ToLower(types[j])
	})
	return types
}

func splitWindow(timeout time.Duration) (time.Duration, time.Duration) {
	first := timeout / 3
	if first <= 0 {
		first = timeout
	}
	return first, timeout - first
}

func mergeResults(results []model.QueryResult) []model.QueryResult {
	type sourceRecords struct {
		source net.IP
		rrs    []dns.RR
		seen   map[string]struct{}
	}

	bySource := make(map[string]*sourceRecords)
	for _, result := range results {
		if result.Source == nil {
			continue
		}
		key := result.Source.String()
		group := bySource[key]
		if group == nil {
			group = &sourceRecords{
				source: cloneIP(result.Source),
				seen:   make(map[string]struct{}),
			}
			bySource[key] = group
		}
		for _, rr := range result.RRs {
			if !supportedRR(rr) {
				continue
			}
			recordKey := rrKey(rr)
			if _, exists := group.seen[recordKey]; exists {
				continue
			}
			group.seen[recordKey] = struct{}{}
			group.rrs = append(group.rrs, rr)
		}
	}

	keys := make([]string, 0, len(bySource))
	for key := range bySource {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytesCompare(bySource[keys[i]].source, bySource[keys[j]].source) < 0
	})

	merged := make([]model.QueryResult, 0, len(keys))
	for _, key := range keys {
		group := bySource[key]
		if len(group.rrs) == 0 {
			continue
		}
		merged = append(merged, model.QueryResult{Source: group.source, RRs: group.rrs})
	}
	return merged
}

func uniqueNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		fqdn := dns.Fqdn(strings.TrimSpace(name))
		key := strings.ToLower(fqdn)
		if fqdn == "." {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, fqdn)
	}
	return result
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func bytesCompare(left, right net.IP) int {
	left16 := left.To16()
	right16 := right.To16()
	for i := range left16 {
		if left16[i] < right16[i] {
			return -1
		}
		if left16[i] > right16[i] {
			return 1
		}
	}
	return 0
}
