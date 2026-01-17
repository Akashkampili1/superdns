package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/akashkampili1/superdns/pkg/analysis"
	"github.com/akashkampili1/superdns/pkg/dnsops"
)

// Result is a duplicate of runner.Result to avoid cycle if runner imports `output`
// Use an interface or shared struct if possible.
// For now, let's just accept interface{} or define a struct here and map it.
// To keep it clean, let's assume the caller passes the structs from `dnsops` and `analysis`.

type ScanResult struct {
	Resolution *dnsops.ResolutionResult `json:"resolution"`
	Analysis   *analysis.Analysis       `json:"analysis"`
}

func WriteJSON(w io.Writer, res ScanResult) {
	enc := json.NewEncoder(w)
	enc.Encode(res)
}

func WriteTable(w io.Writer, res ScanResult) {
	// Simple human readable format
	// DOMAIN | CNAME | STATUS | PROVIDER | RISK
	
	// We want a nice block for each domain if it's detailed
	// Or a single line if summary. let's do a compact block.
	
	fmt.Fprintf(w, "▶ Domain: %s\n", res.Resolution.Domain)
	if len(res.Resolution.Records) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for t, r := range res.Resolution.Records {
			if len(r.Values) > 0 {
				fmt.Fprintf(tw, "  %s\t%s\t(TTL: %d)\n", t, strings.Join(r.Values, ", "), r.TTL)
			} else if r.Status != "NOERROR" && r.Status != "" {
				// Only show errors if specific
				fmt.Fprintf(tw, "  %s\t[%s]\n", t, r.Status)
			}
		}
		tw.Flush()
	}
	
	if res.Analysis.IsDangling {
		fmt.Fprintf(w, "  [!] VULNERABILITY: Potential Dangling CNAME detected pointing to %s\n", res.Analysis.DanglingCNAME)
	}
	if res.Analysis.CloudProvider != "" {
		fmt.Fprintf(w, "  [*] Provider: %s\n", res.Analysis.CloudProvider)
	}
	if res.Resolution.HasWildcard {
		fmt.Fprintf(w, "  [*] Wildcard: Enabled\n")
	}
	fmt.Fprintln(w, strings.Repeat("-", 40))
}
