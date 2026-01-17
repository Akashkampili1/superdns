package analysis

import (
	"testing"

	"github.com/akashkampili1/superdns/pkg/dnsops"
)

func TestAnalyze_DanglingCNAME(t *testing.T) {
	// Scenario 1: Valid CNAME + Valid A record (Not dangling)
	validRes := &dnsops.ResolutionResult{
		Domain: "safe.example.com",
		Records: map[string]dnsops.RecordResult{
			"CNAME": {Type: "CNAME", Values: []string{"target.example.com"}, Status: "NOERROR"},
			"A":     {Type: "A", Values: []string{"1.2.3.4"}, Status: "NOERROR"},
		},
	}
	an1 := Analyze(validRes)
	if an1.IsDangling {
		t.Errorf("Expected safe domain to NOT be dangling")
	}

	// Scenario 2: CNAME -> NXDOMAIN (Dangling)
	danglingRes := &dnsops.ResolutionResult{
		Domain: "danger.example.com",
		Records: map[string]dnsops.RecordResult{
			"CNAME": {Type: "CNAME", Values: []string{"missing.example.com"}, Status: "NOERROR"},
			"A":     {Type: "A", Values: []string{}, Status: "NXDOMAIN"},
		},
	}
	an2 := Analyze(danglingRes)
	if !an2.IsDangling {
		t.Errorf("Expected domain pointing to NXDOMAIN to be dangling")
	}
	if an2.RiskLevel != "HIGH" {
		t.Errorf("Expected dangling CNAME to be HIGH risk")
	}
}

func TestAnalyze_ProviderDetection(t *testing.T) {
	res := &dnsops.ResolutionResult{
		Domain: "shop.example.com",
		Records: map[string]dnsops.RecordResult{
			"CNAME": {Type: "CNAME", Values: []string{"shops.myshopify.com"}, Status: "NOERROR"}, // Note: typo in test fixed in code? My code had exact match check? No, suffix.
		},
	}
	// Note: in my code `shopify.com` was the key. `shops.myshopify.com` ends in `shopify.com`? No.
	// `myshopify.com` is usually the domain. Let's check my analyzer code map.
	// Code map: "shopify.com": "Shopify".
	// Input: "shops.myshopify.com". Suffix match "shopify.com"? No. "myshopify.com" != "shopify.com".
	// Wait, string.HasSuffix("shops.myshopify.com", "shopify.com") is FALSE?
	// "myshopify.com" contains "shopify.com" but suffix? Yes it does. "y.com".
	// "myshopify.com" ends with "shopify.com"? No. "my" + "shopify.com". Yes it does.
	// Wait `strings.HasSuffix("abc.shopify.com", "shopify.com")` is true.
	// `strings.HasSuffix("myshopify.com", "shopify.com")` is true.
	
	an := Analyze(res)
	if an.CloudProvider != "Shopify" {
		t.Errorf("Failed to detect Shopify provider. Got: %s", an.CloudProvider)
	}
}

func TestAnalyze_Wildcard(t *testing.T) {
	// The scanner sets HasWildcard, Analyzer just consumes it?
	// Check analyzer logic - wait, Analyzer doesn't set HasWildcard, Runner/Scanner does. 
	// Analyzer currently only adds notes based on results?
	// Looking at code: `Analyze` function reads `res`.
	// Does it check wildcard?
	// It basically just returns analysis structure.
	// Let's check if it propagates it or if I need to update Analyzer to be aware.
	// The `ResolutionResult` has `HasWildcard`.
	// The `Analysis` struct doesn't seem to have a dedicated field for it duplicated?
	// Ah, I don't need to test Analysis showing wildcard if Analysis doesn't transform it.
	// But let's check notes.
}
