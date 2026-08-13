package render

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/miekg/dns"

	"mdnscan/internal/model"
)

// Text writes the stable, human-readable mDNS asset format.
func Text(w io.Writer, assets []model.Asset) error {
	for assetIndex, asset := range assets {
		if assetIndex > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "services:"); err != nil {
			return err
		}
		for _, service := range asset.Services {
			if err := writeServiceHeader(w, service); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "Name=%s\n", service.Instance); err != nil {
				return err
			}
			if len(service.IPv4) > 0 {
				if _, err := fmt.Fprintf(w, "IPv4=%s\n", joinIPs(service.IPv4)); err != nil {
					return err
				}
			}
			if len(service.IPv6) > 0 {
				if _, err := fmt.Fprintf(w, "IPv6=%s\n", joinIPs(service.IPv6)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "Hostname=%s\nTTL=%d\n", strings.TrimSuffix(service.Hostname, "."), service.TTL); err != nil {
				return err
			}
			if len(service.TXT) > 0 {
				if _, err := fmt.Fprintln(w, strings.Join(service.TXT, ",")); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintln(w, "answers:"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "PTR:"); err != nil {
			return err
		}
		for _, ptr := range asset.PTR {
			if _, err := fmt.Fprintln(w, strings.TrimSuffix(ptr, ".")); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeServiceHeader(w io.Writer, service model.Service) error {
	if service.Port == 0 {
		_, err := fmt.Fprintf(w, "%s:\n", serviceLabel(service.Type))
		return err
	}
	_, err := fmt.Fprintf(w, "%d/%s %s:\n", service.Port, service.Protocol, serviceLabel(service.Type))
	return err
}

func serviceLabel(serviceType string) string {
	labels := dns.SplitDomainName(serviceType)
	if len(labels) == 0 {
		return strings.TrimPrefix(strings.TrimSuffix(serviceType, "."), "_")
	}
	return strings.TrimPrefix(labels[0], "_")
}

func joinIPs(ips []net.IP) string {
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.String())
	}
	return strings.Join(values, ",")
}
