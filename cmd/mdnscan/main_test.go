package main

import (
	"bytes"
	"testing"
)

func TestRunRejectsInvalidArgumentsBeforeDiscovery(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing required flags"},
		{name: "invalid workers", args: []string{"--cidr", "127.0.0.1/32", "--ports", "5000", "--workers", "0"}},
		{name: "invalid CIDR", args: []string{"--cidr", "invalid", "--ports", "5000"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != 2 {
				t.Fatalf("run() code = %d, want 2; stderr=%q", code, stderr.String())
			}
		})
	}
}
