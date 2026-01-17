package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akashkampili1/superdns/pkg/analysis"
	"github.com/akashkampili1/superdns/pkg/dnsops"
	"github.com/akashkampili1/superdns/pkg/output"
)

// Resolver defines the interface for DNS resolution
type Resolver interface {
	GetRecords(ctx context.Context, domain string) (*dnsops.ResolutionResult, error)
}

type Options struct {
	Resolver    string
	Concurrency int
	Timeout     time.Duration
	Input       io.Reader
	Output      io.Writer
	JSONOutput  bool
	OnlyDangling bool
	CustomResolver Resolver // Optional: Injected resolver for testing
}

type Result struct {
	Resolution *dnsops.ResolutionResult `json:"resolution"`
	Analysis   *analysis.Analysis       `json:"analysis"`
}

func Run(opts Options) {
	workChan := make(chan string)
	var wg sync.WaitGroup

	var client Resolver
	if opts.CustomResolver != nil {
		client = opts.CustomResolver
	} else {
		client = dnsops.NewClient(opts.Resolver, opts.Timeout, 2)
	}

	resChan := make(chan Result, opts.Concurrency)
	doneChan := make(chan struct{})

	go func() {
		defer close(doneChan)
		ProcessOutput(resChan, opts)
	}()

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range workChan {
				processDomain(domain, client, resChan)
			}
		}()
	}

	scanner := bufio.NewScanner(opts.Input)
	seen := make(map[string]bool)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		line = strings.TrimSuffix(line, ".")
		if seen[line] {
			continue
		}
		seen[line] = true
		workChan <- line
	}

	close(workChan)
	wg.Wait()
	close(resChan)
	<-doneChan
}

func processDomain(domain string, client Resolver, resChan chan<- Result) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) 
	defer cancel()

	res, err := client.GetRecords(ctx, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error resolving %s: %v\n", domain, err)
		return
	}

	// Wildcard check
	// Note: Wildcard check logic constructs its own queries?
	// Ah, GetRecords is high level. 
	// The original wildcard code was:
	//   wRes, _ := client.GetRecords(ctx, randName)
	// Since our interface has GetRecords, we can use it!
	
	randName := fmt.Sprintf("wildcard-%d.%s", rand.Intn(99999), domain)
	wRes, _ := client.GetRecords(ctx, randName)
	if wRes != nil {
		if a, ok := wRes.Records["A"]; ok && a.Status == "NOERROR" && len(a.Values) > 0 {
			res.HasWildcard = true
		}
	}

	an := analysis.Analyze(res)
	
	resChan <- Result{
		Resolution: res,
		Analysis:   an,
	}
}

func ProcessOutput(resChan <-chan Result, opts Options) {
	for res := range resChan {
		// Filter logic
		if opts.OnlyDangling && !res.Analysis.IsDangling {
			continue
		}

		scanRes := output.ScanResult{
			Resolution: res.Resolution,
			Analysis:   res.Analysis,
		}

		if opts.JSONOutput {
			output.WriteJSON(opts.Output, scanRes)
		} else {
			output.WriteTable(opts.Output, scanRes)
		}
	}
}
