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
	return []model.QueryResult{
		{
			Source: source,
			RRs: []dns.RR{
				// DNS-SD service enumeration.
				mustRR("_services._dns-sd._udp.local. 10 IN PTR _qdiscover._tcp.local."),
				// workstation (port 9)
				mustRR("_workstation._tcp.local. 10 IN PTR slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local."),
				mustRR("slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local. 10 IN SRV 0 0 9 slw-nas.local."),
				mustRR(`slw-nas [24:5e:be:69:a3:13]._workstation._tcp.local. 10 IN TXT ""`),
				// http (port 5000)
				mustRR("_http._tcp.local. 10 IN PTR slw-nas._http._tcp.local."),
				mustRR("slw-nas._http._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local."),
				mustRR(`slw-nas._http._tcp.local. 10 IN TXT "path=/"`),
				// smb (port 445)
				mustRR("_smb._tcp.local. 10 IN PTR slw-nas._smb._tcp.local."),
				mustRR("slw-nas._smb._tcp.local. 10 IN SRV 0 0 445 slw-nas.local."),
				mustRR(`slw-nas._smb._tcp.local. 10 IN TXT ""`),
				// qdiscover (port 5000)
				mustRR("_qdiscover._tcp.local. 10 IN PTR slw-nas._qdiscover._tcp.local."),
				mustRR("slw-nas._qdiscover._tcp.local. 10 IN SRV 0 0 5000 slw-nas.local."),
				mustRR(`slw-nas._qdiscover._tcp.local. 10 IN TXT "accessType=https" "accessPort=86" "model=TS-X64" "displayModel=TS-464C" "fwVer=5.2.9" "fwBuildNum=20260214"`),
				// afpovertcp (port 548)
				mustRR("_afpovertcp._tcp.local. 10 IN PTR slw-nas (AFP)._afpovertcp._tcp.local."),
				mustRR("slw-nas (AFP)._afpovertcp._tcp.local. 10 IN SRV 0 0 548 slw-nas.local."),
				mustRR(`slw-nas (AFP)._afpovertcp._tcp.local. 10 IN TXT ""`),
				// device-info (port 0)
				mustRR("_device-info._tcp.local. 10 IN PTR slw-nas (AFP)._device-info._tcp.local."),
				mustRR("slw-nas (AFP)._device-info._tcp.local. 10 IN SRV 0 0 0 slw-nas.local."),
				mustRR(`slw-nas (AFP)._device-info._tcp.local. 10 IN TXT "model=Xserve"`),
				// A/AAAA records
				mustRR("slw-nas.local. 10 IN A 192.168.1.20"),
				mustRR("slw-nas.local. 10 IN AAAA fe80::265e:beff:fe69:a313"),
			},
		},
	}
}

// QNAP is the stable fixture entry point used by package-level regression tests.
func QNAP() []model.QueryResult {
	return BuildQNAPFixture()
}

func mustRR(raw string) dns.RR {
	rr, err := dns.NewRR(raw)
	if err != nil {
		panic(err)
	}
	return rr
}
