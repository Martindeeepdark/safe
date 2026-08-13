package render_test

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"mdnscan/internal/correlate"
	"mdnscan/internal/render"
	"mdnscan/internal/testfixture"
)

type portSet map[uint16]bool

func (p portSet) Contains(port uint16) bool {
	return p[port]
}

func TestTextQNAPBanner(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	allPorts := portSet{0: true, 9: true, 445: true, 548: true, 5000: true}

	assets := correlate.Build(testfixture.BuildQNAPFixture(), cidr, allPorts)

	var output bytes.Buffer
	if err := render.Text(&output, assets); err != nil {
		t.Fatal(err)
	}

	wantParts := []string{
		"services:\n",
		"5000/tcp qdiscover:\n",
		"Name=slw-nas\n",
		"Hostname=slw-nas.local\n",
		"accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214\n",
		"_qdiscover._tcp.local",
		"_device-info._tcp.local",
		"548/tcp afpovertcp:\n",
		"device-info:\n", // port 0 service should not have port/proto prefix
	}
	for _, part := range wantParts {
		if !strings.Contains(output.String(), part) {
			t.Errorf("output missing %q:\n%s", part, output.String())
		}
	}

	// Check for workstation with special name
	if !strings.Contains(output.String(), "Name=slw-nas [24:5e:be:69:a3:13]") {
		t.Errorf("output missing workstation instance name:\n%s", output.String())
	}
}

func TestTextDeterministic(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}

	allPorts := portSet{0: true, 9: true, 445: true, 548: true, 5000: true}

	assets := correlate.Build(testfixture.BuildQNAPFixture(), cidr, allPorts)

	var out1, out2 bytes.Buffer
	if err := render.Text(&out1, assets); err != nil {
		t.Fatal(err)
	}
	if err := render.Text(&out2, assets); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out1.Bytes(), out2.Bytes()) {
		t.Errorf("render not deterministic")
	}
}
