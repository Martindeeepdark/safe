package discovery

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"

	"mdnscan/internal/model"
)

var mdnsIPv4Address = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: mdnsPort}

func discoverMulticast(ctx context.Context, cfg Config) ([]model.QueryResult, error) {
	localIP, err := interfaceIPv4(cfg.Interface)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open multicast UDP socket: %w", err)
	}
	defer conn.Close()

	packetConn := ipv4.NewPacketConn(conn)
	if cfg.Interface != nil {
		if err := packetConn.SetMulticastInterface(cfg.Interface); err != nil {
			return nil, fmt.Errorf("select multicast interface %s: %w", cfg.Interface.Name, err)
		}
	}
	if err := packetConn.SetMulticastTTL(255); err != nil {
		return nil, fmt.Errorf("set multicast TTL: %w", err)
	}

	metaWindow, detailWindow := splitWindow(cfg.Timeout)
	metaResults, err := exchangeQueries(ctx, conn, mdnsIPv4Address, []string{metaService}, metaWindow, nil)
	if err != nil {
		return metaResults, err
	}

	types := serviceTypes(metaResults)
	if len(types) == 0 {
		types = fallbackServices
	}
	detailResults, err := exchangeQueries(ctx, conn, mdnsIPv4Address, types, detailWindow, nil)
	return append(metaResults, detailResults...), err
}

func interfaceIPv4(networkInterface *net.Interface) (net.IP, error) {
	if networkInterface == nil {
		return nil, nil
	}

	addresses, err := networkInterface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("list addresses for interface %s: %w", networkInterface.Name, err)
	}
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ipv4Address := ip.To4(); ipv4Address != nil {
			return cloneIP(ipv4Address), nil
		}
	}
	return nil, fmt.Errorf("interface %s has no IPv4 address", networkInterface.Name)
}
