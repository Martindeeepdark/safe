package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"mdnscan/internal/correlate"
	"mdnscan/internal/discovery"
	"mdnscan/internal/render"
	"mdnscan/internal/target"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mdnscan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		cidrRaw      string
		portsRaw     string
		interfaceRaw string
		timeout      time.Duration
		workers      int
		maxHosts     int
	)
	flags.StringVar(&cidrRaw, "cidr", "", "IPv4 CIDR to query, for example 192.168.1.0/24")
	flags.StringVar(&portsRaw, "ports", "", "SRV ports to include, for example 9,445,5000-5010")
	flags.StringVar(&interfaceRaw, "interface", "", "network interface used for multicast queries")
	flags.DurationVar(&timeout, "timeout", 3*time.Second, "receive window for each discovery phase")
	flags.IntVar(&workers, "workers", 32, "number of concurrent unicast queries (1-256)")
	flags.IntVar(&maxHosts, "max-hosts", 4096, "maximum number of IPv4 addresses to enumerate")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: mdnscan --cidr CIDR --ports PORTS [flags]")
		fmt.Fprintln(stderr, "mDNS multicast is local-network scoped; per-IP unicast queries are best effort.")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if cidrRaw == "" || portsRaw == "" {
		fmt.Fprintln(stderr, "both --cidr and --ports are required")
		flags.Usage()
		return 2
	}
	if timeout <= 0 {
		fmt.Fprintln(stderr, "--timeout must be greater than zero")
		return 2
	}
	if workers < 1 || workers > 256 {
		fmt.Fprintln(stderr, "--workers must be between 1 and 256")
		return 2
	}

	network, hosts, err := target.ParseCIDR(cidrRaw, maxHosts)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --cidr: %v\n", err)
		return 2
	}
	ports, err := target.ParsePorts(portsRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --ports: %v\n", err)
		return 2
	}

	var iface *net.Interface
	if interfaceRaw != "" {
		iface, err = net.InterfaceByName(interfaceRaw)
		if err != nil {
			fmt.Fprintf(stderr, "invalid --interface: %v\n", err)
			return 2
		}
	}

	results, err := discovery.Discover(context.Background(), discovery.Config{
		CIDR:      network,
		Hosts:     hosts,
		Interface: iface,
		Timeout:   timeout,
		Workers:   workers,
	})
	if err != nil {
		fmt.Fprintf(stderr, "discovery failed: %v\n", err)
		return 1
	}

	assets := correlate.Build(results, network, ports)
	if err := render.Text(stdout, assets); err != nil {
		fmt.Fprintf(stderr, "render failed: %v\n", err)
		return 1
	}
	if len(assets) == 0 {
		fmt.Fprintln(stderr, "no mDNS assets discovered; silent hosts may still provide services")
	}
	return 0
}
