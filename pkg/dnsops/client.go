package dnsops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// RecordResult holds the result of a single DNS record query
type RecordResult struct {
	Type    string   `json:"type"`
	Values  []string `json:"values"`
	TTL     uint32   `json:"ttl"`
	Status  string   `json:"status"` // NOERROR, NXDOMAIN, etc.
	Error   string   `json:"error,omitempty"`
}

// ResolutionResult holds the aggregate results for a domain
type ResolutionResult struct {
	Domain      string                  `json:"domain"`
	Records     map[string]RecordResult `json:"records"`
	CNameChain  []string                `json:"cname_chain,omitempty"`
	IsDangling  bool                    `json:"is_dangling"`
	HasWildcard bool                    `json:"has_wildcard"`
	Nameservers []string                `json:"nameservers,omitempty"`
}

// Client handles DNS queries
type Client struct {
	ResolverAddr string
	Client       *dns.Client
	Retries      int
}

// NewClient creates a new DNS client
func NewClient(resolver string, timeout time.Duration, retries int) *Client {
	if resolver == "" {
		// Default to Google DNS or system if needed, but let's use 8.8.8.8:53 as reliable default for scanning
		// or read from /etc/resolv.conf (too complex for now, user flag usually provided)
		resolver = "8.8.8.8:53"
	}
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}

	return &Client{
		ResolverAddr: resolver,
		Client: &dns.Client{
			Timeout: timeout,
			Net:     "udp",
		},
		Retries: retries,
	}
}

// Query sends a DNS query for a specific type
func (c *Client) Query(ctx context.Context, domain string, qtype uint16) (*dns.Msg, error) {
	asciiDomain, err := idna.ToASCII(domain)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(asciiDomain), qtype)
	m.RecursionDesired = true

	var r *dns.Msg

	for i := 0; i <= c.Retries; i++ {
		r, _, err = c.Client.ExchangeContext(ctx, m, c.ResolverAddr)
		if err == nil {
			return r, nil
		}
		// logic for backoff could go here
		time.Sleep(50 * time.Millisecond)
	}
	return nil, err
}

// GetRecords queries specific record types for a domain
func (c *Client) GetRecords(ctx context.Context, domain string) (*ResolutionResult, error) {
	result := &ResolutionResult{
		Domain:  domain,
		Records: make(map[string]RecordResult),
	}

	types := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS,
		dns.TypeMX, dns.TypeTXT, dns.TypeSOA, // dns.TypeCAA, dns.TypeSRV (Omitted for speed unless requested, but req says include)
	}
	// Add req types
	types = append(types, dns.TypeSRV, dns.TypeCAA)

	// We essentially need to chase CNAMEs to detect dangling status
	// But first, let's just get the raw records requested
	
	for _, t := range types {
		// Check context
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		mt, _ := dns.TypeToString[t]
		msg, err := c.Query(ctx, domain, t)
		
		recRes := RecordResult{Type: mt}
		
		if err != nil {
			recRes.Error = err.Error()
			recRes.Status = "ERROR"
		} else {
			recRes.Status = dns.RcodeToString[msg.Rcode]
			if msg.Rcode == dns.RcodeSuccess {
				for _, ans := range msg.Answer {
					// Extract data based on type
					val := ""
					header := ans.Header()
					recRes.TTL = header.Ttl

					switch v := ans.(type) {
					case *dns.A:
						val = v.A.String()
					case *dns.AAAA:
						val = v.AAAA.String()
					case *dns.CNAME:
						val = v.Target
					case *dns.NS:
						val = v.Ns
					case *dns.MX:
						val = fmt.Sprintf("%d %s", v.Preference, v.Mx)
					case *dns.TXT:
						val = strings.Join(v.Txt, " ")
					case *dns.SOA:
						val = fmt.Sprintf("%s %s %d", v.Ns, v.Mbox, v.Serial)
					case *dns.SRV:
						val = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
					case *dns.CAA:
						val = fmt.Sprintf("%d %s %s", v.Flag, v.Tag, v.Value)
					case *dns.PTR:
						val = v.Ptr
					}
					if val != "" {
						recRes.Values = append(recRes.Values, val)
					}
				}
			}
		}
		result.Records[mt] = recRes
	}
	
	return result, nil
}
