package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wplatnick/ghbom/internal/github"
)

// ScanResult holds the result of scanning a single repository.
type ScanResult struct {
	Repo     string
	Findings  []github.Finding
	Error    error
	HasError bool
}

// ScanRepo scans a single repository for compromised actions.
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

	// Run abom scan
	cmd := exec.Command("abom", "scan", clonePath, "--check")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// abom exits 1 when no workflows found — distinguish from real errors
		errStr := string(out)
		isNoWorkflows := strings.Contains(errStr, "no such file or directory") &&
			strings.Contains(errStr, ".github/workflows")
		if !isNoWorkflows {
			result.Error = fmt.Errorf("abom scan failed: %s", errStr)
			result.HasError = true
			return result
		}
		// Exit 1 with no workflows = not an error, just skip
	}

	result.Findings = github.ParseAbomOutput(string(out))
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
