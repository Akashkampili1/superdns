package api_test

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestIntegration runs the built binary against a sample input.
// Requires invalid or dummy domains to avoid reliance on external state,
// or performs a dry run.
func TestCLI_Smoke(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("Skipping integration test; use INTEGRATION=1 to run")
	}

	// 1. Build binary
	cmd := exec.Command("go", "build", "-o", "../dnsscan_test", "../cmd/dnsscan/main.go")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer os.Remove("../dnsscan_test")

	// 2. Run against a known domain (example.com)
	runCmd := exec.Command("../dnsscan_test", "-d", "example.com")
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Run failed: %v\nOutput: %s", err, string(out))
	}

	if !strings.Contains(string(out), "example.com") {
		t.Errorf("Output did not contain domain name")
	}
	if !strings.Contains(string(out), "A") { // Should have A record
		t.Errorf("Output did not contain A record")
	}
}
