package testfixture

import (
	"net"

	"github.com/miekg/dns"

	"mdnscan/internal/model"
)

// BuildQNAPFixture returns a []model.QueryResult representing a single
// QNAP NAS responder at 192.168.1.20 advertising 6 services matching
// the requirement example.
func BuildQNAPFixture() []model.QueryResult {
	source := net.ParseIP("192.168.1.20")
	ipv4 := net.ParseIP("192.168.1.20")
	ipv6 := net.ParseIP("fe80::265e:beff:fe69:a313")

	hdr := func(name string, rrtype uint16, ttl uint32) dns.RR_Header {
		return dns.RR_Header{
			Name:   name,
			Rrtype: rrtype,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
	}

	// Common A/AAAA records
	a := &dns.A{Hdr: hdr("slw-nas.local.", dns.TypeA, 10), A: ipv4}
	aaaa := &dns.AAAA{Hdr: hdr("slw-nas.local.", dns.TypeAAAA, 10), AAAA: ipv6}

	// workstation (port 9) - instance name with MAC address in brackets
	workstationInstance := "slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local."
	workstationPTR := &dns.PTR{Hdr: hdr("_workstation._tcp.local.", dns.TypePTR, 10), Ptr: workstationInstance}
	workstationSRV := &dns.SRV{Hdr: hdr(workstationInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 9, Target: "slw-nas.local."}
	workstationTXT := &dns.TXT{Hdr: hdr(workstationInstance, dns.TypeTXT, 10), Txt: []string{}}

	// http (port 5000)
	httpInstance := "slw-nas._http._tcp.local."
	httpPTR := &dns.PTR{Hdr: hdr("_http._tcp.local.", dns.TypePTR, 10), Ptr: httpInstance}
	httpSRV := &dns.SRV{Hdr: hdr(httpInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 5000, Target: "slw-nas.local."}
	httpTXT := &dns.TXT{Hdr: hdr(httpInstance, dns.TypeTXT, 10), Txt: []string{"path=/"}}

	// smb (port 445)
	smbInstance := "slw-nas._smb._tcp.local."
	smbPTR := &dns.PTR{Hdr: hdr("_smb._tcp.local.", dns.TypePTR, 10), Ptr: smbInstance}
	smbSRV := &dns.SRV{Hdr: hdr(smbInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 445, Target: "slw-nas.local."}
	smbTXT := &dns.TXT{Hdr: hdr(smbInstance, dns.TypeTXT, 10), Txt: []string{}}

	// qdiscover (port 5000)
	qdiscoverInstance := "slw-nas._qdiscover._tcp.local."
	qdiscoverPTR := &dns.PTR{Hdr: hdr("_qdiscover._tcp.local.", dns.TypePTR, 10), Ptr: qdiscoverInstance}
	qdiscoverSRV := &dns.SRV{Hdr: hdr(qdiscoverInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 5000, Target: "slw-nas.local."}
	qdiscoverTXT := &dns.TXT{Hdr: hdr(qdiscoverInstance, dns.TypeTXT, 10), Txt: []string{
		"accessType=https",
		"accessPort=86",
		"model=TS-X64",
		"displayModel=TS-464C",
		"fwVer=5.2.9",
		"fwBuildNum=20260214",
	}}

	// afpovertcp (port 548)
	afpInstance := "slw-nas (AFP)._afpovertcp._tcp.local."
	afpPTR := &dns.PTR{Hdr: hdr("_afpovertcp._tcp.local.", dns.TypePTR, 10), Ptr: afpInstance}
	afpSRV := &dns.SRV{Hdr: hdr(afpInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 548, Target: "slw-nas.local."}
	afpTXT := &dns.TXT{Hdr: hdr(afpInstance, dns.TypeTXT, 10), Txt: []string{}}

	// device-info (port 0)
	deviceInfoInstance := "slw-nas (AFP)._device-info._tcp.local."
	deviceInfoPTR := &dns.PTR{Hdr: hdr("_device-info._tcp.local.", dns.TypePTR, 10), Ptr: deviceInfoInstance}
	deviceInfoSRV := &dns.SRV{Hdr: hdr(deviceInfoInstance, dns.TypeSRV, 10), Priority: 0, Weight: 0, Port: 0, Target: "slw-nas.local."}
	deviceInfoTXT := &dns.TXT{Hdr: hdr(deviceInfoInstance, dns.TypeTXT, 10), Txt: []string{"model=Xserve"}}

	rrs := []dns.RR{
		workstationPTR, workstationSRV, workstationTXT,
		httpPTR, httpSRV, httpTXT,
		smbPTR, smbSRV, smbTXT,
		qdiscoverPTR, qdiscoverSRV, qdiscoverTXT,
		afpPTR, afpSRV, afpTXT,
		deviceInfoPTR, deviceInfoSRV, deviceInfoTXT,
		a, aaaa,
	}

	return []model.QueryResult{
		{Source: source, RRs: rrs},
	}
}

// QNAP is the stable fixture entry point used by package-level regression tests.
func QNAP() []model.QueryResult {
	return BuildQNAPFixture()
}
