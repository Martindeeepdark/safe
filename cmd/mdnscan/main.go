package main

import (
	"fmt"
	"os"
)

// main is intentionally minimal during parallel agent work. The coordinator
// wires it to target, discovery, correlate, and render at integration time.
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		printUsage(os.Stdout)
		return
	}
	fmt.Fprintln(os.Stderr, "mdnscan: not yet wired (bootstrap state)")
	printUsage(os.Stderr)
	os.Exit(2)
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mdnscan --cidr CIDR --ports PORTS [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Required:")
	fmt.Fprintln(w, "  --cidr       IPv4 CIDR, e.g. 192.168.1.0/24")
	fmt.Fprintln(w, "  --ports      Comma-separated ports and ranges, e.g. 9,445,5000-5010")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Optional:")
	fmt.Fprintln(w, "  --timeout    Per-phase receive window, default 3s")
	fmt.Fprintln(w, "  --interface  Network interface name; empty for system default")
	fmt.Fprintln(w, "  --workers    Unicast concurrency, default 32, max 256")
	fmt.Fprintln(w, "  --max-hosts  Host enumeration cap, default 4096")
}
