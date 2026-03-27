package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wplatnick/ghbom/internal/github"
	"github.com/wplatnick/ghbom/internal/output"
	"github.com/wplatnick/ghbom/internal/scanner"
)

var (
	flagOrg         string
	flagConcurrency int
	flagFormat      string
	flagOutput      string
	flagSkipExisting bool
)

func init() {
	flag.StringVar(&flagOrg, "org", "", "GitHub organization (required)")
	flag.IntVar(&flagConcurrency, "concurrency", 5, "Number of parallel scans")
	flag.StringVar(&flagFormat, "format", "text", "Output format: text, json, sarif")
	flag.StringVar(&flagOutput, "output", "", "Output file (default stdout)")
	flag.BoolVar(&flagSkipExisting, "skip-existing", false, "Skip repos that don't have workflow files")
}

func main() {
	flag.Parse()

	if flagOrg == "" {
		fmt.Fprintln(os.Stderr, "Error: --org is required")
		flag.Usage()
		os.Exit(1)
	}

	if flagConcurrency < 1 {
		fmt.Fprintln(os.Stderr, "Error: --concurrency must be at least 1")
		os.Exit(1)
	}

	if flagFormat != "text" && flagFormat != "json" && flagFormat != "sarif" {
		fmt.Fprintf(os.Stderr, "Error: --format must be text, json, or sarif, got: %s\n", flagFormat)
		os.Exit(1)
	}

	// Check rate limit before starting
	fmt.Println("Checking GitHub API rate limit...")
	if err := github.WaitForRateLimit(10); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not check rate limit: %v\n", err)
	}

	// List repositories
	fmt.Printf("Fetching repositories for org: %s\n", flagOrg)
	repos, err := github.ListRepos(flagOrg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing repos: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d repositories\n", len(repos))

	// Filter repos with workflows if --skip-existing is set
	var filteredRepos []github.Repo
	if flagSkipExisting {
		fmt.Println("Filtering repos with workflows...")
		for _, repo := range repos {
			hasWorkflows, err := github.HasWorkflows(flagOrg, repo.Name)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not check workflows for %s: %v\n", repo.Name, err)
				continue
			}
			if hasWorkflows {
				filteredRepos = append(filteredRepos, repo)
			}
		}
		fmt.Printf("Found %d repos with workflows\n", len(filteredRepos))
	} else {
		filteredRepos = repos
	}

	if len(filteredRepos) == 0 {
		fmt.Println("No repos to scan.")
		os.Exit(0)
	}

	// Create scanner
	sc, err := scanner.NewScanner(flagOrg, flagConcurrency)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scanner: %v\n", err)
		os.Exit(1)
	}

	// Progress printer
	progress := scanner.NewProgressPrinter(len(filteredRepos))

	// Start scanning
	fmt.Printf("Starting scan with concurrency %d...\n", flagConcurrency)

	// Start scanner in background
	go sc.Scan(filteredRepos)

	// Collect results with progress reporting
	var collectedResults []scanner.ScanResult
	for result := range sc.Results() {
		if result.HasError {
			fmt.Fprintf(os.Stderr, "[ERROR] %s: %v\n", result.Repo, result.Error)
		} else {
			progress.Print(result.Repo)
		}
		collectedResults = append(collectedResults, result)
	}

	// Convert collected results back to channel for formatters
	resultsChan := make(chan scanner.ScanResult, len(collectedResults))
	for _, r := range collectedResults {
		resultsChan <- r
	}
	close(resultsChan)

	// Format output
	var formatter interface {
		Format(<-chan scanner.ScanResult) error
	}

	switch flagFormat {
	case "json":
		formatter = output.NewJSONFormatter(flagOutput)
	case "sarif":
		formatter = output.NewSARIFFormatter(flagOutput)
	default:
		tf, err := output.NewTextFormatter(flagOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating formatter: %v\n", err)
			os.Exit(1)
		}
		formatter = tf
	}

	if err := formatter.Format(resultsChan); err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}

	if flagOutput != "" && flagOutput != "-" {
		fmt.Printf("Output written to: %s\n", flagOutput)
	}
}
