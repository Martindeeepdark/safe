package target

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ParseCIDR parses and expands an IPv4 CIDR, including its network and
// broadcast addresses.
func ParseCIDR(raw string, maxHosts int) (*net.IPNet, []net.IP, error) {
	if maxHosts <= 0 {
		return nil, nil, fmt.Errorf("maxHosts must be greater than zero")
	}

	_, parsedNet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("parse CIDR %q: %w", raw, err)
	}

	ones, bits := parsedNet.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("CIDR %q is not IPv4", raw)
	}

	addressCount := uint64(1) << uint(bits-ones)
	if addressCount > uint64(maxHosts) {
		return nil, nil, fmt.Errorf("CIDR %q contains %d addresses, exceeding limit %d", raw, addressCount, maxHosts)
	}

	networkIP := parsedNet.IP.To4()
	if networkIP == nil {
		return nil, nil, fmt.Errorf("CIDR %q is not IPv4", raw)
	}

	network := &net.IPNet{
		IP:   append(net.IP(nil), networkIP...),
		Mask: append(net.IPMask(nil), parsedNet.Mask...),
	}
	hosts := make([]net.IP, int(addressCount))
	base := binary.BigEndian.Uint32(networkIP)
	for i := uint64(0); i < addressCount; i++ {
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, base+uint32(i))
		hosts[i] = ip
	}

	return network, hosts, nil
}
