package target

import (
	"net"
	"reflect"
	"testing"
)

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

func TestParseCIDRSingleAddress(t *testing.T) {
	network, hosts, err := ParseCIDR("203.0.113.7/32", 1)
	if err != nil {
		t.Fatalf("ParseCIDR() error = %v", err)
	}
	if got, want := network.String(), "203.0.113.7/32"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}
	if len(hosts) != 1 {
		t.Fatalf("len(hosts) = %d, want 1", len(hosts))
	}
	if got, want := hosts[0].String(), "203.0.113.7"; got != want {
		t.Fatalf("hosts[0] = %q, want %q", got, want)
	}
}

func TestParseCIDRExpandsIPv4Network(t *testing.T) {
	network, hosts, err := ParseCIDR("192.0.2.4/30", 4)
	if err != nil {
		t.Fatalf("ParseCIDR() error = %v", err)
	}
	if got, want := network.String(), "192.0.2.4/30"; got != want {
		t.Fatalf("network = %q, want %q", got, want)
	}

	want := []string{"192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"}
	if len(hosts) != len(want) {
		t.Fatalf("len(hosts) = %d, want %d", len(hosts), len(want))
	}
	for i := range want {
		if got := hosts[i].String(); got != want[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, got, want[i])
		}
	}

	hosts[0][0] = 203
	if hosts[1].Equal(net.ParseIP("203.0.2.5")) {
		t.Fatal("host IP slices share backing storage")
	}
}

func TestParseCIDRRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		maxHosts int
	}{
		{name: "IPv6", raw: "2001:db8::/126", maxHosts: 4},
		{name: "host limit", raw: "192.0.2.0/29", maxHosts: 4},
		{name: "all IPv4 addresses exceed limit", raw: "0.0.0.0/0", maxHosts: 1},
		{name: "zero limit", raw: "192.0.2.0/30", maxHosts: 0},
		{name: "negative limit", raw: "192.0.2.0/30", maxHosts: -1},
		{name: "invalid CIDR", raw: "not-a-cidr", maxHosts: 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseCIDR(tt.raw, tt.maxHosts); err == nil {
				t.Fatal("ParseCIDR() error = nil, want error")
			}
		})
	}
}

func TestParseCIDRDesignDocCases(t *testing.T) {
	t.Run("/24 network includes network and broadcast", func(t *testing.T) {
		_, hosts, err := ParseCIDR("192.168.1.0/24", 256)
		if err != nil {
			t.Fatalf("ParseCIDR() error = %v", err)
		}
		if len(hosts) != 256 {
			t.Fatalf("len(hosts) = %d, want 256", len(hosts))
		}
		if got := hosts[0].String(); got != "192.168.1.0" {
			t.Errorf("hosts[0] = %q, want 192.168.1.0", got)
		}
		if got := hosts[255].String(); got != "192.168.1.255" {
			t.Errorf("hosts[255] = %q, want 192.168.1.255", got)
		}
	})

	t.Run("/30 network has 4 hosts", func(t *testing.T) {
		_, hosts, err := ParseCIDR("10.0.0.0/30", 4)
		if err != nil {
			t.Fatalf("ParseCIDR() error = %v", err)
		}
		if len(hosts) != 4 {
			t.Fatalf("len(hosts) = %d, want 4", len(hosts))
		}
	})

	t.Run("respects maxHosts limit", func(t *testing.T) {
		_, _, err := ParseCIDR("192.168.1.0/24", 255)
		if err == nil {
			t.Fatal("ParseCIDR() error = nil, want error for exceeding maxHosts")
		}
	})

	t.Run("allows exactly maxHosts", func(t *testing.T) {
		_, _, err := ParseCIDR("192.168.1.0/24", 256)
		if err != nil {
			t.Fatalf("ParseCIDR() error = %v", err)
		}
	})

	t.Run("rejects IPv6", func(t *testing.T) {
		_, _, err := ParseCIDR("2001:db8::/32", 1000000000)
		if err == nil {
			t.Fatal("ParseCIDR() error = nil, want error for IPv6")
		}
	})

	t.Run("rejects invalid CIDR", func(t *testing.T) {
		_, _, err := ParseCIDR("not-a-cidr", 256)
		if err == nil {
			t.Fatal("ParseCIDR() error = nil, want error for invalid CIDR")
		}
	})
}
