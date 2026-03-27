package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ghbom/ghbom/internal/abom/pkg/advisory"
	"github.com/ghbom/ghbom/internal/abom/pkg/model"
	"github.com/ghbom/ghbom/internal/abom/pkg/parser"
	"github.com/ghbom/ghbom/internal/abom/pkg/resolver"
	"github.com/ghbom/ghbom/internal/github"
)

// ScanResult holds the result of scanning a single repository.
type ScanResult struct {
	Repo     string
	Findings []github.Finding
	Error    error
	HasError bool
}

// ScanRepo scans a single repository for compromised actions using the abom Go API.
func ScanRepo(org, repo, cloneDir string, token string) ScanResult {
	result := ScanResult{Repo: repo}

	// Create clone directory
	clonePath := filepath.Join(cloneDir, org, repo)
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		result.Error = fmt.Errorf("failed to create clone dir: %w", err)
		result.HasError = true
		return result
	}

	// Clone the repo
	if err := github.CloneRepo(org, repo, token, clonePath); err != nil {
		result.Error = fmt.Errorf("clone failed: %w", err)
		result.HasError = true
		return result
	}

	// Cleanup after scan (only the specific repo clone dir)
	defer os.RemoveAll(clonePath)

	// Parse workflows
	workflows, err := parser.ParseWorkflowDir(clonePath)
	if err != nil {
		errStr := err.Error()
		// If the workflows directory doesn't exist, that's not an error —
		// it just means no workflows to scan. Match the original abom behavior.
		if strings.Contains(errStr, "no such file or directory") && strings.Contains(errStr, ".github/workflows") {
			return result
		}
		result.Error = fmt.Errorf("parsing workflows: %w", err)
		result.HasError = true
		return result
	}

	if len(workflows) == 0 {
		// No workflows — not an error, just skip
		return result
	}

	// Create ABOM
	abom := model.NewABOM(clonePath)
	abom.Workflows = workflows

	// Resolve transitive dependencies
	res, err := resolver.New(resolver.Options{
		MaxDepth:  10,
		Token:     token,
		NoNetwork: false,
		Quiet:     true,
		LocalRoot: clonePath,
	})
	if err != nil {
		result.Error = fmt.Errorf("initializing resolver: %w", err)
		result.HasError = true
		return result
	}

	if err := res.ResolveWorkflows(workflows); err != nil {
		result.Error = fmt.Errorf("resolving dependencies: %w", err)
		result.HasError = true
		return result
	}

	// Check advisories
	db := advisory.NewDatabase(advisory.LoadOptions{
		Offline: false,
		NoCache: false,
		Quiet:   true,
		Token:   token,
	})
	db.CheckAll(abom)

	// Collect actions
	abom.CollectActions()

	// Convert compromised actions to findings
	for _, action := range abom.Actions {
		if action.Compromised {
			// Use the first "referenced by" as location context
			loc := ".github/workflows"
			if len(action.ReferencedBy) > 0 {
				loc = action.ReferencedBy[0]
			}
			finding := github.Finding{
				RuleID:   action.Advisory,
				Level:    "error",
				Message:  fmt.Sprintf("compromised action: %s", action.Raw),
				Location: loc,
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	return result
}

// Scanner manages concurrent repository scanning.
type Scanner struct {
	org         string
	concurrency int
	token       string
	cloneDir    string
	sem         chan struct{}
	wg          sync.WaitGroup
	results     chan ScanResult
}

// NewScanner creates a new Scanner instance.
func NewScanner(org string, concurrency int) (*Scanner, error) {
	token, err := github.GetAuthToken()
	if err != nil {
		return nil, err
	}

	return &Scanner{
		org:         org,
		concurrency: concurrency,
		token:       token,
		cloneDir:    "/tmp/ghbom",
		sem:         make(chan struct{}, concurrency),
		results:     make(chan ScanResult, 100),
	}, nil
}

// Scan repositories concurrently and send results to the results channel.
func (s *Scanner) Scan(repos []github.Repo) {
	for _, repo := range repos {
		s.wg.Add(1)
		go func(r github.Repo) {
			s.sem <- struct{}{}
			defer func() {
				<-s.sem
				s.wg.Done()
			}()

			result := ScanRepo(s.org, r.Name, s.cloneDir, s.token)
			s.results <- result
		}(repo)
	}

	go func() {
		s.wg.Wait()
		close(s.results)
	}()
}

// Results returns the results channel.
func (s *Scanner) Results() <-chan ScanResult {
	return s.results
}

// ProgressPrinter prints scan progress.
type ProgressPrinter struct {
	total int
	count int
	mu    sync.Mutex
}

// NewProgressPrinter creates a new progress printer.
func NewProgressPrinter(total int) *ProgressPrinter {
	return &ProgressPrinter{total: total}
}

// Print prints progress for a scanned repo.
func (p *ProgressPrinter) Print(repo string) {
	p.mu.Lock()
	p.count++
	fmt.Printf("[%d/%d] Scanning %s...\n", p.count, p.total, repo)
	p.mu.Unlock()
}
