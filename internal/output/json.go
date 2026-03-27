package output

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/wplatnick/ghbom/internal/scanner"
)

// JSONFinding represents a finding in JSON output format.
type JSONFinding struct {
	Repo     string `json:"repo"`
	RuleID   string `json:"ruleId"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Location string `json:"location,omitempty"`
}

// JSONReport is the top-level JSON output structure.
type JSONReport struct {
	Version   string        `json:"version"`
	ScannedAt string        `json:"scannedAt"`
	TotalRepos int          `json:"totalRepos"`
	ReposWithFindings int   `json:"reposWithFindings"`
	TotalFindings int      `json:"totalFindings"`
	Findings  []JSONFinding `json:"findings"`
}

// JSONFormatter outputs results in JSON format.
type JSONFormatter struct {
	path string
}

// NewJSONFormatter creates a new JSONFormatter.
func NewJSONFormatter(path string) *JSONFormatter {
	return &JSONFormatter{path: path}
}

// Format outputs scan results in JSON format.
func (f *JSONFormatter) Format(results <-chan scanner.ScanResult) error {
	var allFindings []scanner.ScanResult
	for r := range results {
		allFindings = append(allFindings, r)
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Repo < allFindings[j].Repo
	})

	report := JSONReport{
		Version: "1.0.0",
		TotalRepos: len(allFindings),
	}

	for _, r := range allFindings {
		if r.HasError {
			continue
		}
		for _, finding := range r.Findings {
			report.TotalFindings++
			report.Findings = append(report.Findings, JSONFinding{
				Repo:     r.Repo,
				RuleID:   finding.RuleID,
				Level:    finding.Level,
				Message:  finding.Message,
				Location: finding.Location,
			})
		}
		if len(r.Findings) > 0 {
			report.ReposWithFindings++
		}
	}

	var out *os.File
	if f.path == "" || f.path == "-" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.Create(f.path)
		if err != nil {
			return err
		}
		defer out.Close()
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
