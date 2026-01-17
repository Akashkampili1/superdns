package dnsops

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startMockDNSServer(t *testing.T) (*dns.Server, string) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	
	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true

			for _, q := range r.Question {
				switch q.Name {
				case "example.com.":
					if q.Qtype == dns.TypeA {
						rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
						m.Answer = append(m.Answer, rr)
					}
				case "cname.example.com.":
					if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeA { // Respond to A for CNAME too usually, or just CNAME
						rr, _ := dns.NewRR("cname.example.com. 3600 IN CNAME target.example.com.")
						m.Answer = append(m.Answer, rr)
						// recursive resolvers follow, but we are mocking an auth server or simple resolver
						// If client just asks CNAME, give CNAME.
					}
				case "timeout.com.":
					// Don't reply (client will timeout)
					return
				}
			}
			w.WriteMsg(m)
		}),
	}

	go func() {
		server.ActivateAndServe()
	}()

	return server, pc.LocalAddr().String()
}

func TestGetRecords(t *testing.T) {
	srv, addr := startMockDNSServer(t)
	defer srv.Shutdown()

	client := NewClient(addr, 2*time.Second, 1)

	// Test 1: A Record
	ctx := context.Background()
	res, err := client.GetRecords(ctx, "example.com")
	if err != nil {
		t.Fatalf("GetRecords failed: %v", err)
	}
	if len(res.Records["A"].Values) == 0 {
		t.Errorf("Expected A record, got none")
	}
	if res.Records["A"].Values[0] != "1.2.3.4" {
		t.Errorf("Expected 1.2.3.4, got %v", res.Records["A"].Values[0])
	}

	// Test 2: Timeout
	// We need a short timeout for test
	fastClient := NewClient(addr, 200*time.Millisecond, 0)
	_, err = fastClient.GetRecords(ctx, "timeout.com")
	// GetRecords generally suppresses individual errors but returns them in the map, OR if the context dies?
	// GetRecords loops over types. If one times out, do we fail whole?
	// The implementation checks ctx.Done().
	
	// Let's check `timeout.com`.
	// The loop will try A, AAAA, etc.
	// Since the mock server hangs, we expect `GetRecords` to take `200ms * num_types` roughly?
	// Or context error?
	
	// Actually GetRecords uses `c.Query` which uses `c.Client.ExchangeContext`. 
	// The client has a timeout.
	// `client.go`: `res.Records` will likely contain Error strings.
}
