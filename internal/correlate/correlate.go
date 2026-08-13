package correlate

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"mdnscan/internal/model"
)

type sourcedRR[T dns.RR] struct {
	rr     T
	source net.IP
}

type indexes struct {
	ptrs  map[string][]sourcedRR[*dns.PTR]
	srvs  map[string][]sourcedRR[*dns.SRV]
	txts  map[string][]sourcedRR[*dns.TXT]
	addr4 map[string][]sourcedRR[*dns.A]
	addr6 map[string][]sourcedRR[*dns.AAAA]
}

type assetBuilder struct {
	hostname string
	ipv4     map[string]net.IP
	ipv6     map[string]net.IP
	services map[string]model.Service
	ptr      map[string]string
}

// Build correlates DNS-SD records into stable, host-oriented assets.
func Build(results []model.QueryResult, cidr *net.IPNet, ports interface{ Contains(uint16) bool }) []model.Asset {
	if cidr == nil || ports == nil {
		return nil
	}

	idx := buildIndexes(results)
	assets := make(map[string]*assetBuilder)

	for typeKey, ptrs := range idx.ptrs {
		serviceType := serviceName(typeKey)
		protocol := serviceProtocol(typeKey)
		if protocol == "" {
			continue
		}

		for _, ptr := range ptrs {
			instanceKey := fqdnKey(ptr.rr.Ptr)
			for _, srv := range idx.srvs[instanceKey] {
				isDeviceInfo := srv.rr.Port == 0 && strings.EqualFold(serviceType, "device-info")
				if !isDeviceInfo && !ports.Contains(srv.rr.Port) {
					continue
				}

				hostKey := fqdnKey(srv.rr.Target)
				ipv4 := ipv4ForHost(idx.addr4[hostKey])
				ipv6 := ipv6ForHost(idx.addr6[hostKey])
				if !anyIPInCIDR(ipv4, cidr) && !relatedSourceInCIDR(cidr, ptr.source, srv.source, idx.txts[instanceKey], idx.addr4[hostKey], idx.addr6[hostKey]) {
					continue
				}

				service := model.Service{
					Instance: instanceName(ptr.rr.Ptr, typeKey),
					Type:     serviceType,
					Protocol: protocol,
					Port:     uint16(srv.rr.Port),
					Hostname: strings.TrimSuffix(srv.rr.Target, "."),
					IPv4:     ipv4,
					IPv6:     ipv6,
					TXT:      txtForInstance(idx.txts[instanceKey]),
				}
				ttlCandidates := append([]uint32{srv.rr.Header().Ttl}, txtTTLs(idx.txts[instanceKey])...)
				service.TTL = minimumTTL(ptr.rr.Header().Ttl, ttlCandidates...)
				service.TTL = minimumTTL(service.TTL, addressTTLs(idx.addr4[hostKey], idx.addr6[hostKey])...)

				builder := assets[hostKey]
				if builder == nil {
					builder = &assetBuilder{
						hostname: service.Hostname,
						ipv4:     make(map[string]net.IP),
						ipv6:     make(map[string]net.IP),
						services: make(map[string]model.Service),
						ptr:      make(map[string]string),
					}
					assets[hostKey] = builder
				}
				addIPs(builder.ipv4, service.IPv4)
				addIPs(builder.ipv6, service.IPv6)
				builder.ptr[typeKey] = strings.TrimSuffix(typeKey, ".")
				builder.services[serviceKey(service)] = service
			}
		}
	}

	return finalizeAssets(assets)
}

func buildIndexes(results []model.QueryResult) indexes {
	idx := indexes{
		ptrs:  make(map[string][]sourcedRR[*dns.PTR]),
		srvs:  make(map[string][]sourcedRR[*dns.SRV]),
		txts:  make(map[string][]sourcedRR[*dns.TXT]),
		addr4: make(map[string][]sourcedRR[*dns.A]),
		addr6: make(map[string][]sourcedRR[*dns.AAAA]),
	}
	seen := make(map[string]struct{})

	for _, result := range results {
		for _, rr := range result.RRs {
			if rr == nil {
				continue
			}
			key := rrKey(rr, result.Source)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			owner := fqdnKey(rr.Header().Name)
			switch record := rr.(type) {
			case *dns.PTR:
				idx.ptrs[owner] = append(idx.ptrs[owner], sourcedRR[*dns.PTR]{rr: record, source: cloneIP(result.Source)})
			case *dns.SRV:
				idx.srvs[owner] = append(idx.srvs[owner], sourcedRR[*dns.SRV]{rr: record, source: cloneIP(result.Source)})
			case *dns.TXT:
				idx.txts[owner] = append(idx.txts[owner], sourcedRR[*dns.TXT]{rr: record, source: cloneIP(result.Source)})
			case *dns.A:
				idx.addr4[owner] = append(idx.addr4[owner], sourcedRR[*dns.A]{rr: record, source: cloneIP(result.Source)})
			case *dns.AAAA:
				idx.addr6[owner] = append(idx.addr6[owner], sourcedRR[*dns.AAAA]{rr: record, source: cloneIP(result.Source)})
			}
		}
	}

	return idx
}

func rrKey(rr dns.RR, source net.IP) string {
	return source.String() + "|" + strings.ToLower(rr.String())
}

func fqdnKey(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

func serviceProtocol(serviceType string) string {
	labels := dns.SplitDomainName(serviceType)
	for _, label := range labels {
		switch strings.ToLower(label) {
		case "_tcp":
			return "tcp"
		case "_udp":
			return "udp"
		}
	}
	return ""
}

func serviceName(serviceType string) string {
	labels := dns.SplitDomainName(serviceType)
	if len(labels) == 0 {
		return strings.TrimPrefix(strings.TrimSuffix(serviceType, "."), "_")
	}
	return strings.TrimPrefix(labels[0], "_")
}

func instanceName(instance, serviceType string) string {
	instance = strings.TrimSuffix(instance, ".")
	serviceType = strings.TrimSuffix(serviceType, ".")
	suffix := "." + serviceType
	if len(instance) >= len(suffix) && strings.EqualFold(instance[len(instance)-len(suffix):], suffix) {
		return instance[:len(instance)-len(suffix)]
	}
	return instance
}

func ipv4ForHost(records []sourcedRR[*dns.A]) []net.IP {
	unique := make(map[string]net.IP)
	for _, record := range records {
		if ip := record.rr.A.To4(); ip != nil {
			unique[ip.String()] = cloneIP(ip)
		}
	}
	return sortedIPs(unique)
}

func ipv6ForHost(records []sourcedRR[*dns.AAAA]) []net.IP {
	unique := make(map[string]net.IP)
	for _, record := range records {
		if ip := record.rr.AAAA; ip != nil && ip.To4() == nil && ip.To16() != nil {
			unique[ip.String()] = cloneIP(ip)
		}
	}
	return sortedIPs(unique)
}

func anyIPInCIDR(ips []net.IP, cidr *net.IPNet) bool {
	for _, ip := range ips {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func relatedSourceInCIDR(
	cidr *net.IPNet,
	ptrSource net.IP,
	srvSource net.IP,
	txts []sourcedRR[*dns.TXT],
	addr4 []sourcedRR[*dns.A],
	addr6 []sourcedRR[*dns.AAAA],
) bool {
	if cidr.Contains(ptrSource) || cidr.Contains(srvSource) {
		return true
	}
	for _, record := range txts {
		if cidr.Contains(record.source) {
			return true
		}
	}
	for _, record := range addr4 {
		if cidr.Contains(record.source) {
			return true
		}
	}
	for _, record := range addr6 {
		if cidr.Contains(record.source) {
			return true
		}
	}
	return false
}

func txtForInstance(records []sourcedRR[*dns.TXT]) []string {
	seen := make(map[string]struct{})
	var txt []string
	for _, record := range records {
		for _, value := range record.rr.Txt {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			txt = append(txt, value)
		}
	}
	return txt
}

func txtTTLs(records []sourcedRR[*dns.TXT]) []uint32 {
	ttls := make([]uint32, 0, len(records))
	for _, record := range records {
		ttls = append(ttls, record.rr.Header().Ttl)
	}
	return ttls
}

func addressTTLs(addr4 []sourcedRR[*dns.A], addr6 []sourcedRR[*dns.AAAA]) []uint32 {
	ttls := make([]uint32, 0, len(addr4)+len(addr6))
	for _, record := range addr4 {
		ttls = append(ttls, record.rr.Header().Ttl)
	}
	for _, record := range addr6 {
		ttls = append(ttls, record.rr.Header().Ttl)
	}
	return ttls
}

func minimumTTL(first uint32, rest ...uint32) uint32 {
	minimum := first
	for _, ttl := range rest {
		if ttl != 0 && (minimum == 0 || ttl < minimum) {
			minimum = ttl
		}
	}
	return minimum
}

func serviceKey(service model.Service) string {
	return fqdnKey(service.Type) + "|" + fqdnKey(service.Instance) + "|" + fqdnKey(service.Hostname) + "|" + service.Protocol + "|" + strconv.FormatUint(uint64(service.Port), 10)
}

func addIPs(target map[string]net.IP, ips []net.IP) {
	for _, ip := range ips {
		target[ip.String()] = cloneIP(ip)
	}
}

func finalizeAssets(builders map[string]*assetBuilder) []model.Asset {
	assets := make([]model.Asset, 0, len(builders))
	for _, builder := range builders {
		asset := model.Asset{
			Hostname: builder.hostname,
			IPv4:     sortedIPs(builder.ipv4),
			IPv6:     sortedIPs(builder.ipv6),
			Services: make([]model.Service, 0, len(builder.services)),
			PTR:      make([]string, 0, len(builder.ptr)),
		}
		for _, service := range builder.services {
			asset.Services = append(asset.Services, service)
		}
		for _, ptr := range builder.ptr {
			asset.PTR = append(asset.PTR, ptr)
		}
		sort.Slice(asset.Services, func(i, j int) bool {
			left, right := asset.Services[i], asset.Services[j]
			if left.Port != right.Port {
				return left.Port < right.Port
			}
			if left.Protocol != right.Protocol {
				return left.Protocol < right.Protocol
			}
			if left.Type != right.Type {
				return left.Type < right.Type
			}
			return left.Instance < right.Instance
		})
		sort.Strings(asset.PTR)
		assets = append(assets, asset)
	}
	sort.Slice(assets, func(i, j int) bool {
		return strings.ToLower(assets[i].Hostname) < strings.ToLower(assets[j].Hostname)
	})
	return assets
}

func sortedIPs(unique map[string]net.IP) []net.IP {
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ips := make([]net.IP, 0, len(keys))
	for _, key := range keys {
		ips = append(ips, cloneIP(unique[key]))
	}
	return ips
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
