package target

import "testing"

func TestParsePorts(t *testing.T) {
	set, err := ParsePorts("9,445,5000-5002")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}

	// Contains 9, 445, 5000, 5001, 5002; does not contain 10.
	for _, port := range []uint16{9, 445, 5000, 5001, 5002} {
		if !set.Contains(port) {
			t.Errorf("Contains(%d) = false, want true", port)
		}
	}
	if set.Contains(10) {
		t.Error("Contains(10) = true, want false")
	}
}

func TestParsePortsTrimWhitespace(t *testing.T) {
	ports, err := ParsePorts(" 9, 445, 5000 - 5002 ")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}

	for _, port := range []uint16{9, 445, 5000, 5001, 5002} {
		if !ports.Contains(port) {
			t.Errorf("Contains(%d) = false, want true", port)
		}
	}
	for _, port := range []uint16{0, 10, 444, 5003, 65535} {
		if ports.Contains(port) {
			t.Errorf("Contains(%d) = true, want false", port)
		}
	}
}

func TestParsePortsRejectsInvalidExpressions(t *testing.T) {
	tests := []string{
		"",          // empty string
		"0",         // zero port
		"65536",     // exceeds max
		"5000-4000", // start > end
		"80-",       // missing end
		"abc",       // non-numeric
		"80,,443",   // empty item
		// Additional cases from draft implementation
		" ",
		"5002-5000",
		"-5000",
		"5000--5002",
		"http",
		"9, ,445",
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParsePorts(raw); err == nil {
				t.Fatal("ParsePorts() error = nil, want error")
			}
		})
	}
}

func TestParsePortsDesignDocCases(t *testing.T) {
	ports, err := ParsePorts("9,445,5000-5010")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}

	// Test positive cases
	tests := []struct {
		port     uint16
		expected bool
	}{
		{9, true},
		{445, true},
		{5000, true},
		{5010, true},
		{450, false},
		{5011, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := ports.Contains(tt.port)
			if got != tt.expected {
				t.Errorf("Contains(%d) = %v, want %v", tt.port, got, tt.expected)
			}
		})
	}
}
