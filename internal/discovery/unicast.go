package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"mdnscan/internal/model"
)

func discoverUnicast(ctx context.Context, cfg Config, hosts []net.IP) ([]model.QueryResult, error) {
	if len(hosts) == 0 {
		return nil, nil
	}
	phaseCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	workers := cfg.Workers
	if workers > len(hosts) {
		workers = len(hosts)
	}

	jobs := make(chan net.IP)
	results := make(chan []model.QueryResult, workers)
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for host := range jobs {
				if phaseCtx.Err() != nil {
					return
				}
				result, err := queryUnicastHost(phaseCtx, cfg, host)
				if err != nil {
					if phaseCtx.Err() != nil {
						return
					}
					continue
				}
				if len(result) == 0 {
					continue
				}
				select {
				case results <- result:
				case <-phaseCtx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			ipv4Address := host.To4()
			if ipv4Address == nil {
				continue
			}
			select {
			case jobs <- cloneIP(ipv4Address):
			case <-phaseCtx.Done():
				return
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	var collected []model.QueryResult
	for result := range results {
		collected = append(collected, result...)
	}
	if err := ctx.Err(); err != nil {
		return collected, err
	}
	if errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
		return collected, nil
	}
	return collected, nil
}

func queryUnicastHost(ctx context.Context, cfg Config, host net.IP) ([]model.QueryResult, error) {
	localIP, err := interfaceIPv4(cfg.Interface)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open unicast UDP socket for %s: %w", host, err)
	}
	defer conn.Close()

	destination := &net.UDPAddr{IP: host.To4(), Port: mdnsPort}
	metaWindow, detailWindow := splitWindow(cfg.Timeout)
	metaResults, err := exchangeQueries(ctx, conn, destination, []string{metaService}, metaWindow, host)
	if err != nil {
		return metaResults, classifyUnicastError(host, err)
	}

	types := serviceTypes(metaResults)
	if len(types) == 0 {
		types = fallbackServices
	}
	detailResults, err := exchangeQueries(ctx, conn, destination, types, detailWindow, host)
	if err != nil {
		return append(metaResults, detailResults...), classifyUnicastError(host, err)
	}
	return append(metaResults, detailResults...), nil
}

func classifyUnicastError(host net.IP, err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	return fmt.Errorf("query mDNS host %s: %w", host, err)
}

func hostsFromCIDR(network *net.IPNet) []net.IP {
	if network == nil {
		return nil
	}
	first := network.IP.Mask(network.Mask).To4()
	if first == nil {
		return nil
	}

	var hosts []net.IP
	for ip := cloneIP(first); network.Contains(ip); incrementIPv4(ip) {
		hosts = append(hosts, cloneIP(ip))
	}
	return hosts
}

func incrementIPv4(ip net.IP) {
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			return
		}
	}
}
