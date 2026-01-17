package analysis

import (
	"testing"
	"github.com/akashkampili1/superdns/pkg/dnsops"
)

func BenchmarkAnalyze(b *testing.B) {
	res := &dnsops.ResolutionResult{
		Domain: "bench.example.com",
		Records: map[string]dnsops.RecordResult{
			"CNAME": {Type: "CNAME", Values: []string{"target.shopify.com"}, Status: "NOERROR"},
			"A":     {Type: "A", Values: []string{}, Status: "NXDOMAIN"},
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Analyze(res)
	}
}
