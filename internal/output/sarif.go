package output

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/wplatnick/ghbom/internal/scanner"
)

// SARIFLocation represents a location in SARIF format.
type SARIFLocation struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents a physical location in SARIF.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation represents an artifact location in SARIF.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFMessage represents a message in SARIF.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFResult represents a result in SARIF format.
type SARIFResult struct {
	RuleID  string        `json:"ruleId"`
	Level   string        `json:"level"`
	Message SARIFMessage  `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

// ToolDriver represents the tool driver in SARIF.
type ToolDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool represents the tool in SARIF.
type Tool struct {
	Driver ToolDriver `json:"driver"`
}

// SARIFRun represents a run in SARIF format.
type SARIFRun struct {
	Tool    Tool          `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFOutput represents the top-level SARIF output.
type SARIFOutput struct {
	Version string   `json:"version"`
	Schema  string   `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFFormatter outputs results in SARIF format.
type SARIFFormatter struct {
	path string
}

// NewSARIFFormatter creates a new SARIFFormatter.
func NewSARIFFormatter(path string) *SARIFFormatter {
	return &SARIFFormatter{path: path}
}

// Format outputs scan results in SARIF format.
func (f *SARIFFormatter) Format(results <-chan scanner.ScanResult) error {
	var allFindings []scanner.ScanResult
	for r := range results {
		allFindings = append(allFindings, r)
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Repo < allFindings[j].Repo
	})

	var sarifResults []SARIFResult
	for _, r := range allFindings {
		if r.HasError {
			continue
		}
		for _, finding := range r.Findings {
			loc := finding.Location
			if loc == "" {
				loc = ".github/workflows"
			}
			sarifResults = append(sarifResults, SARIFResult{
				RuleID: finding.RuleID,
				Level:  "error",
				Message: SARIFMessage{
					Text: finding.Message,
				},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI: loc,
							},
						},
					},
				},
			})
		}
	}

	sarif := SARIFOutput{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: Tool{
					Driver: ToolDriver{
						Name:    "ghbom",
						Version: "0.1.0",
					},
				},
				Results: sarifResults,
			},
		},
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
	return enc.Encode(sarif)
}

// SetTimestamp sets the scan timestamp in SARIF output (not currently used, reserved for future).
func SetTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
