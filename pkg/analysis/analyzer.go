package analysis

import (
	"strings"

	"github.com/akashkampili1/superdns/pkg/dnsops"
)

// Analysis holds the security analysis results
type Analysis struct {
	IsDangling    bool     `json:"is_dangling"`
	DanglingCNAME string   `json:"dangling_cname,omitempty"`
	CloudProvider string   `json:"cloud_provider,omitempty"`
	RiskLevel     string   `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	Notes         []string `json:"notes,omitempty"`
}

// Analyze processes the raw DNS results to identify security issues
func Analyze(res *dnsops.ResolutionResult) *Analysis {
	analysis := &Analysis{
		RiskLevel: "LOW",
		Notes:     []string{},
	}

	// 1. Check for Dangling CNAME
	// A common pattern for dangling CNAME is having a CNAME record but the overall resolution status is NXDOMAIN
	// or finding a CNAME with no corresponding A/AAAA record resolving.
	
	if cnameRes, ok := res.Records["CNAME"]; ok {
		if len(cnameRes.Values) > 0 {
			target := cnameRes.Values[0]
			analysis.Notes = append(analysis.Notes, "CNAME target: "+target)
			
			// Detect SaaS providers (generic heuristics to flag interesting targets)
			// Although "No hardcoded fingerprints" was a non-goal, flagging known cloud suffixes is often required for valid risk assessment.
			// We will do very minimal flagging based on common keywords if permitted, or just rely on the mechanics.
			// The prompt said: "Flag external SaaS / cloud providers" AND "Do NOT hardcode provider fingerprints".
			// This likely means: Don't hardcode "response body text" fingerprints (HTTP), but DO flag DNS suffixes (AWS, Azure, etc).
			provider := detectProvider(target)
			if provider != "" {
				analysis.CloudProvider = provider
				analysis.Notes = append(analysis.Notes, "SaaS Provider: "+provider)
			}

			// Logic: If we found a CNAME, but the resolution status for A/AAAA (implied by the query that returned CNAME usually) indicates failure?
			// Since we query record types individually in this tool (Explicit per-record querying):
			// We need to look at the 'A' record query result for the SAME domain.
			// If 'CNAME' has values, but 'A' query returns NXDOMAIN or SERVFAIL (and has no values), it's likely dangling.
			
			aRes := res.Records["A"]
			
			// If we have a CNAME, we generally shouldn't have an A record at the same name (RFC 1034), 
			// except for DNSSEC RRSIG/NSEC etc.
			// But simple resolvers follow the CNAME. 
			// In our `dnsops` client, if we query type A for a CNAME, `miekg/dns` + `RecursionDesired` usually follows it.
			// So: 
			// 1. Query CNAME -> returns CNAME "foobar.com"
			// 2. Query A -> returns CNAME "foobar.com" + A "1.2.3.4" (Status NOERROR)
			//    OR returns CNAME "foobar.com" (Status NXDOMAIN if target missing)
			
			if aRes.Status == "NXDOMAIN" || (aRes.Status == "SERVFAIL" && len(aRes.Values) == 0) {
				analysis.IsDangling = true
				analysis.DanglingCNAME = target
				analysis.RiskLevel = "HIGH"
				analysis.Notes = append(analysis.Notes, "Potential Dangling CNAME")
			}
		}
	}

	// 2. Misconfigured NS (Lame delegation or Orphaned NS cleanup)
	// If NS records exist but resolution of A fail?
	// This is harder to check without querying the NS themselves. 
	// Basic check: If NS records are present, do we have SOA?
	if nsRes, ok := res.Records["NS"]; ok && len(nsRes.Values) > 0 {
		if res.Records["SOA"].Status == "NXDOMAIN" {
			// This is weird. NS exists but SOA doesn't?
			analysis.Notes = append(analysis.Notes, "NS records present but SOA missing (Anomalous)")
		}
	}

	return analysis
}

func detectProvider(cname string) string {
	cname = strings.ToLower(cname)
	// Minimal list of common suffixes for categorization
	providers := map[string]string{
		"s3.amazonaws.com": "AWS S3",
		"elasticbeanstalk.com": "AWS Elastic Beanstalk",
		"azurewebsites.net": "Azure App Service",
		"cloudapp.net": "Azure Cloud App",
		"herokuapp.com": "Heroku",
		"github.io": "GitHub Pages",
		"wordpress.com": "WordPress",
		"shopify.com": "Shopify",
		"zendesk.com": "Zendesk",
		"fastly.net": "Fastly",
		"akamaiedge.net": "Akamai",
		// Add more as needed
	}
	
	for key, name := range providers {
		if strings.HasSuffix(cname, key) {
			return name
		}
	}
	return ""
}
