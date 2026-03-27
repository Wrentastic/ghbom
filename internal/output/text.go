package output

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ghbom/ghbom/internal/scanner"
)

// TextFormatter outputs results in human-readable text format.
type TextFormatter struct {
	w *os.File
}

// NewTextFormatter creates a new TextFormatter writing to the given file (or stdout).
func NewTextFormatter(path string) (*TextFormatter, error) {
	if path == "" || path == "-" {
		return &TextFormatter{w: os.Stdout}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &TextFormatter{w: f}, nil
}

// Format outputs scan results in text format.
func (f *TextFormatter) Format(results <-chan scanner.ScanResult) error {
	var allFindings []scanner.ScanResult
	for r := range results {
		allFindings = append(allFindings, r)
	}

	// Sort by repo name
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Repo < allFindings[j].Repo
	})

	totalRepos := len(allFindings)
	totalFindings := 0
	reposWithFindings := 0

	fmt.Fprintln(f.w, "=== GitHub Actions Bill of Materials Scan Results ===")
	fmt.Fprintln(f.w)

	for _, r := range allFindings {
		if r.HasError {
			fmt.Fprintf(f.w, "[ERROR] %s: %v\n", r.Repo, r.Error)
			continue
		}
		if len(r.Findings) > 0 {
			reposWithFindings++
			totalFindings += len(r.Findings)
			fmt.Fprintf(f.w, "[FINDINGS] %s (%d issues)\n", r.Repo, len(r.Findings))
			for _, finding := range r.Findings {
				loc := finding.Location
				if loc == "" {
					loc = ".github/workflows"
				}
				fmt.Fprintf(f.w, "  - [%s] %s (%s)\n", finding.RuleID, finding.Message, loc)
			}
			fmt.Fprintln(f.w)
		}
	}

	fmt.Fprintln(f.w, "=== Summary ===")
	fmt.Fprintf(f.w, "Total repos scanned: %d\n", totalRepos)
	fmt.Fprintf(f.w, "Repos with findings: %d\n", reposWithFindings)
	fmt.Fprintf(f.w, "Total findings: %d\n", totalFindings)

	if f.w != os.Stdout {
		f.w.Close()
	}
	return nil
}

// EscapeString escapes special characters for text output.
func EscapeString(s string) string {
	return strings.ReplaceAll(s, "\n", " ")
}
