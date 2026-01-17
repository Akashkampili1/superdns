package runner

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/akashkampili1/superdns/pkg/dnsops"
)

type MockResolver struct {
	ResolveFunc func(domain string) (*dnsops.ResolutionResult, error)
}

func (m *MockResolver) GetRecords(ctx context.Context, domain string) (*dnsops.ResolutionResult, error) {
	return m.ResolveFunc(domain)
}

func TestRun_ConcurrencyAndFlow(t *testing.T) {
	domains := []string{"foo.com", "bar.com", "baz.com", "dangler.com"}
	inputData := strings.Join(domains, "\n")
	input := strings.NewReader(inputData)
	outputBuf := new(bytes.Buffer)

	mock := &MockResolver{
		ResolveFunc: func(domain string) (*dnsops.ResolutionResult, error) {
			// Basic mock response
			res := &dnsops.ResolutionResult{
				Domain:  domain,
				Records: make(map[string]dnsops.RecordResult),
			}
			
			// If Wildcard check calls us with "wildcard-...", we return NXDOMAIN usually
			if strings.HasPrefix(domain, "wildcard-") {
				res.Records["A"] = dnsops.RecordResult{Status: "NXDOMAIN"}
				return res, nil
			}

			if domain == "dangler.com" {
				res.Records["CNAME"] = dnsops.RecordResult{Values: []string{"dead.target.com"}, Status: "NOERROR"}
				res.Records["A"] = dnsops.RecordResult{Status: "NXDOMAIN"} // dangling logic
			} else {
				res.Records["A"] = dnsops.RecordResult{Values: []string{"1.2.3.4"}, Status: "NOERROR"}
			}
			return res, nil
		},
	}

	opts := Options{
		Input:          input,
		Output:         outputBuf,
		CustomResolver: mock,
		Concurrency:    2,
		JSONOutput:     false,
		OnlyDangling:   false,
	}

	Run(opts)

	out := outputBuf.String()
	
	// Verify output contains all domains
	for _, d := range domains {
		if !strings.Contains(out, d) {
			t.Errorf("Output missing domain: %s", d)
		}
	}
	
	// Verify Dangling detection in output text
	if !strings.Contains(out, "VULNERABILITY: Potential Dangling CNAME") {
		t.Errorf("Output missing dangling warning")
	}
}

func TestRun_Filtering(t *testing.T) {
	input := strings.NewReader("foo.com\ndangler.com")
	outputBuf := new(bytes.Buffer)

	mock := &MockResolver{
		ResolveFunc: func(domain string) (*dnsops.ResolutionResult, error) {
			res := &dnsops.ResolutionResult{
				Domain:  domain,
				Records: make(map[string]dnsops.RecordResult),
			}
			if strings.HasPrefix(domain, "wildcard-") { return res, nil }

			if domain == "dangler.com" {
				res.Records["CNAME"] = dnsops.RecordResult{Values: []string{"dead.com"}, Status: "NOERROR"}
				res.Records["A"] = dnsops.RecordResult{Status: "NXDOMAIN"} 
			} else {
				res.Records["A"] = dnsops.RecordResult{Values: []string{"1.1.1.1"}, Status: "NOERROR"}
			}
			return res, nil
		},
	}

	opts := Options{
		Input:          input,
		Output:         outputBuf,
		CustomResolver: mock,
		OnlyDangling:   true, // FILTER ON
		Concurrency:    1,
	}

	Run(opts)

	out := outputBuf.String()
	if strings.Contains(out, "foo.com") {
		t.Errorf("Expected foo.com to be filtered out")
	}
	if !strings.Contains(out, "dangler.com") {
		t.Errorf("Expected dangler.com to be present")
	}
}
