package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/akashkampili1/superdns/pkg/runner"
)

const banner = `
                                                         /$$                    
                                                        | $$                    
  /$$$$$$$ /$$   /$$  /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$$   /$$$$$$$
 /$$_____/| $$  | $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$__  $$ /$$_____/
|  $$$$$$ | $$  | $$| $$  \ $$| $$$$$$$$| $$  \__/| $$  | $$| $$  \ $$|  $$$$$$ 
 \____  $$| $$  | $$| $$  | $$| $$_____/| $$      | $$  | $$| $$  | $$ \____  $$
 /$$$$$$$/|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$      |  $$$$$$$| $$  | $$ /$$$$$$$/
|_______/  \______/ | $$____/  \_______/|__/       \_______/|__/  |__/|_______/ 
                    | $$                                                        
                    | $$                                                        
                    |__/                                                        
`

func main() {
	fmt.Fprintf(os.Stderr, "%s\n", banner)

	var (
		domain       string
		listFile     string
		resolver     string
		concurrency  int
		timeout      int
		jsonOutput   bool
		onlyDangling bool
	)

	flag.StringVar(&domain, "d", "", "Single domain to scan")
	flag.StringVar(&domain, "domain", "", "Single domain to scan")
	flag.StringVar(&listFile, "l", "", "File containing list of domains")
	flag.StringVar(&listFile, "list", "", "File containing list of domains")
	flag.StringVar(&resolver, "r", "8.8.8.8:53", "Custom DNS resolver (ip:port)")
	flag.StringVar(&resolver, "resolver", "8.8.8.8:53", "Custom DNS resolver (ip:port)")
	flag.IntVar(&concurrency, "c", 20, "Number of concurrent workers")
	flag.IntVar(&concurrency, "concurrency", 20, "Number of concurrent workers")
	flag.IntVar(&timeout, "t", 5, "Timeout per query in seconds")
	flag.IntVar(&timeout, "timeout", 5, "Timeout per query in seconds")
	flag.BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	flag.BoolVar(&onlyDangling, "only-dangling", false, "Only output domains with potential takeover risks")
	// flag.BoolVar(&onlyCname, "only-cname", false, "Only output domains with CNAME records") // To be implemented if strictly needed, but let's stick to core reqs

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -d example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -l domains.txt -c 50 --json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat domains.txt | %s --only-dangling\n", os.Args[0])
	}

	flag.Parse()

	// Input handling
	var inputReader *os.File = os.Stdin

	// If domain is provided, use it
	if domain != "" {
		// Create a pipe or just use a string reader, but the runner expects io.Reader
		// simpler: pipe
		r, w, _ := os.Pipe()
		go func() {
			w.WriteString(domain + "\n")
			w.Close()
		}()
		inputReader = r
	} else if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening list file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		inputReader = f // This is risky if we assign *os.File to a var? No, it's fine.
		// Wait, inputReader is *os.File (Stdin usually), let's make it io.Reader
	} else {
		// check if stdin has data?
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Println("No input provided. Use -d, -l or pipe into stdin.")
			flag.Usage()
			os.Exit(1)
		}
	}

	opts := runner.Options{
		Resolver:     resolver,
		Concurrency:  concurrency,
		Timeout:      time.Duration(timeout) * time.Second,
		Input:        inputReader, // implicit conversion to io.Reader
		Output:       os.Stdout,
		JSONOutput:   jsonOutput,
		OnlyDangling: onlyDangling,
	}

	runner.Run(opts)
}
