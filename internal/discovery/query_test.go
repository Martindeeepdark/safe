package discovery

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"mdnscan/internal/model"
)

func TestNewPTRQuery(t *testing.T) {
	query := newPTRQuery("_http._tcp.local")

	if query.Id != 0 {
		t.Fatalf("query ID = %d, want 0", query.Id)
	}
	if len(query.Question) != 1 {
		t.Fatalf("question count = %d, want 1", len(query.Question))
	}
	question := query.Question[0]
	if question.Name != "_http._tcp.local." {
		t.Errorf("question name = %q, want FQDN", question.Name)
	}
	if question.Qtype != dns.TypePTR {
		t.Errorf("question type = %d, want PTR", question.Qtype)
	}
	if question.Qclass != dns.ClassINET|1<<15 {
		t.Errorf("question class = %#x, want IN with QU bit", question.Qclass)
	}
}

func TestExtractRRsCollectsSupportedSectionsAndDeduplicates(t *testing.T) {
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{Name: metaService, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 10},
		Ptr: "_http._tcp.local.",
	}
	srv := &dns.SRV{
		Hdr:    dns.RR_Header{Name: "nas._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 10},
		Port:   5000,
		Target: "nas.local.",
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "nas._http._tcp.local.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 10},
		Txt: []string{"path=/", "model=TS-X64"},
	}
	ipv4Address := &dns.A{
		Hdr: dns.RR_Header{Name: "nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   net.ParseIP("192.0.2.10").To4(),
	}
	ipv6Address := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "nas.local.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 10},
		AAAA: net.ParseIP("2001:db8::10"),
	}

	message := &dns.Msg{
		Answer: []dns.RR{ptr, srv},
		Ns:     []dns.RR{ptr, txt},
		Extra:  []dns.RR{ipv4Address, ipv6Address, &dns.MX{}},
	}
	records := extractRRs(message)

	if len(records) != 5 {
		t.Fatalf("record count = %d, want 5", len(records))
	}
}

func TestMergeResultsDeduplicatesPerSourceIgnoringTTL(t *testing.T) {
	source := net.ParseIP("192.0.2.10")
	first := &dns.A{
		Hdr: dns.RR_Header{Name: "nas.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10},
		A:   source.To4(),
	}
	second := &dns.A{
		Hdr: dns.RR_Header{Name: "NAS.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 9},
		A:   source.To4(),
	}

	merged := mergeResults([]model.QueryResult{
		{Source: source, RRs: []dns.RR{first}},
		{Source: source, RRs: []dns.RR{second}},
	})
	if len(merged) != 1 {
		t.Fatalf("result count = %d, want 1", len(merged))
	}
	if len(merged[0].RRs) != 1 {
		t.Fatalf("record count = %d, want 1", len(merged[0].RRs))
	}
}

func TestDiscoverRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "zero timeout", cfg: Config{Timeout: 0, Workers: 1}},
		{name: "negative timeout", cfg: Config{Timeout: -time.Second, Workers: 1}},
		{name: "zero workers", cfg: Config{Timeout: time.Second, Workers: 0}},
		{name: "too many workers", cfg: Config{Timeout: time.Second, Workers: 257}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Discover(context.Background(), test.cfg); err == nil {
				t.Fatal("Discover returned nil error for invalid config")
			}
		})
	}
}
