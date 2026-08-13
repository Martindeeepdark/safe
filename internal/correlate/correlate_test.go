package correlate_test

import (
	"net"
	"testing"

	"mdnscan/internal/correlate"
	"mdnscan/internal/testfixture"
)

type portSet map[uint16]bool

func (p portSet) Contains(port uint16) bool {
	return p[port]
}

func TestBuildQNAP(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	assets := correlate.Build(testfixture.BuildQNAPFixture(), cidr, portSet{5000: true})
	if len(assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(assets))
	}
	asset := assets[0]
	if asset.Hostname != "slw-nas.local" {
		t.Fatalf("hostname = %q", asset.Hostname)
	}
	if len(asset.IPv4) != 1 || asset.IPv4[0].String() != "192.168.1.20" {
		t.Fatalf("IPv4 = %v", asset.IPv4)
	}
	if len(asset.IPv6) != 1 || asset.IPv6[0].String() != "fe80::265e:beff:fe69:a313" {
		t.Fatalf("IPv6 = %v", asset.IPv6)
	}
	// With port 5000 only, should get http and qdiscover services
	if len(asset.Services) != 2 {
		t.Fatalf("service count = %d, want 2 (http + qdiscover)", len(asset.Services))
	}
	// Check that qdiscover service is present
	qdiscoverFound := false
	for _, svc := range asset.Services {
		if svc.Type == "qdiscover" {
			qdiscoverFound = true
			if svc.Instance != "slw-nas" {
				t.Fatalf("qdiscover instance = %q, want slw-nas", svc.Instance)
			}
			if svc.Protocol != "tcp" || svc.Port != 5000 || svc.TTL != 10 {
				t.Fatalf("qdiscover endpoint = %#v", svc)
			}
			wantTXT := []string{
				"accessType=https",
				"accessPort=86",
				"model=TS-X64",
				"displayModel=TS-464C",
				"fwVer=5.2.9",
				"fwBuildNum=20260214",
			}
			if len(svc.TXT) != len(wantTXT) {
				t.Fatalf("TXT = %v", svc.TXT)
			}
			for i := range wantTXT {
				if svc.TXT[i] != wantTXT[i] {
					t.Fatalf("TXT[%d] = %q, want %q", i, svc.TXT[i], wantTXT[i])
				}
			}
		}
	}
	if !qdiscoverFound {
		t.Fatal("qdiscover service not found")
	}
}

func TestBuildFiltersPort(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// With port 445 only, should get smb service only
	assets := correlate.Build(testfixture.BuildQNAPFixture(), cidr, portSet{445: true})
	if len(assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(assets))
	}
	if len(assets[0].Services) != 1 {
		t.Fatalf("service count = %d, want 1 (smb only)", len(assets[0].Services))
	}
	if assets[0].Services[0].Type != "smb" {
		t.Fatalf("got service type %q, want smb", assets[0].Services[0].Type)
	}
}

func TestBuildDeduplicatesRecords(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	results := testfixture.BuildQNAPFixture()
	results = append(results, results[0])

	assets := correlate.Build(results, cidr, portSet{5000: true})
	if len(assets) != 1 || len(assets[0].Services) != 2 || len(assets[0].IPv4) != 1 || len(assets[0].IPv6) != 1 {
		t.Fatalf("duplicate records leaked into output: %#v", assets)
	}
}

func TestBuildAllPorts(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	// Port set that allows all ports including 0
	allPorts := portSet{}
	for i := uint16(0); i <= 65535; i++ {
		allPorts[i] = true
	}

	assets := correlate.Build(testfixture.BuildQNAPFixture(), cidr, allPorts)
	if len(assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(assets))
	}
	asset := assets[0]
	// Should have 6 services: workstation, http, smb, qdiscover, afpovertcp, device-info
	if len(asset.Services) != 6 {
		t.Fatalf("service count = %d, want 6", len(asset.Services))
	}

	// Check device-info (port 0) is present
	deviceInfoFound := false
	for _, svc := range asset.Services {
		if svc.Type == "device-info" {
			deviceInfoFound = true
			if svc.Port != 0 {
				t.Fatalf("device-info port = %d, want 0", svc.Port)
			}
			if len(svc.TXT) != 1 || svc.TXT[0] != "model=Xserve" {
				t.Fatalf("device-info TXT = %v", svc.TXT)
			}
		}
	}
	if !deviceInfoFound {
		t.Fatal("device-info service not found")
	}

	// Check PTR service types
	if len(asset.PTR) != 6 {
		t.Fatalf("PTR count = %d, want 6", len(asset.PTR))
	}
}
