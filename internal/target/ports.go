package target

import (
	"fmt"
	"strconv"
	"strings"
)

// PortSet reports whether a port was selected by the parsed expression.
type PortSet interface {
	Contains(port uint16) bool
}

type portSet struct {
	ports [1 << 16]bool
}

func (s *portSet) Contains(port uint16) bool {
	return s.ports[port]
}

// ParsePorts parses comma-separated ports and inclusive ranges.
func ParsePorts(raw string) (PortSet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("port expression must not be empty")
	}

	result := &portSet{}
	for _, rawItem := range strings.Split(raw, ",") {
		item := strings.TrimSpace(rawItem)
		if item == "" {
			return nil, fmt.Errorf("port expression contains an empty item")
		}

		switch strings.Count(item, "-") {
		case 0:
			port, err := parsePort(item)
			if err != nil {
				return nil, err
			}
			result.ports[port] = true
		case 1:
			bounds := strings.SplitN(item, "-", 2)
			start, err := parsePort(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", item, err)
			}
			end, err := parsePort(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range %q: %w", item, err)
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range %q: start exceeds end", item)
			}
			for port := uint32(start); port <= uint32(end); port++ {
				result.ports[uint16(port)] = true
			}
		default:
			return nil, fmt.Errorf("invalid port range %q", item)
		}
	}

	return result, nil
}

func parsePort(raw string) (uint16, error) {
	if raw == "" {
		return 0, fmt.Errorf("port must not be empty")
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("invalid port %q", raw)
		}
	}

	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("port %q must be between 1 and 65535", raw)
	}
	return uint16(value), nil
}
