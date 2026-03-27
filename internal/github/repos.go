package github

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Repo represents a GitHub repository.
type Repo struct {
	Name string
}

// ListRepos returns all repository names for the given organization.
func ListRepos(org string) ([]Repo, error) {
	cmd := exec.Command("gh", "repo", "list", org, "--json", "name", "--limit", "999999")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list repos: %w", err)
	}

	var results []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Errorf("failed to parse repo list: %w", err)
	}

	repos := make([]Repo, len(results))
	for i, r := range results {
		repos[i] = Repo{Name: r.Name}
	}
	return repos, nil
}

// HasWorkflows checks if a repository has GitHub Actions workflows.
func HasWorkflows(org, repo string) (bool, error) {
	cmd := exec.Command("gh", "api", fmt.Sprintf("repos/%s/%s/actions/workflows", org, repo))
	_, err := cmd.Output()
	if err != nil {
		// Check if it's a "no workflows" error (404 or empty)
		if strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, fmt.Errorf("failed to check workflows: %w", err)
	}
	return true, nil
}

// GetAuthToken returns the GitHub auth token.
func GetAuthToken() (string, error) {
	cmd := exec.Command("gh", "auth", "token")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get auth token: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// RateLimit represents GitHub API rate limit status.
type RateLimit struct {
	Remaining int
	Limit      int
	Reset      time.Time
}

// CheckRateLimit checks the current GitHub API rate limit.
func CheckRateLimit() (*RateLimit, error) {
	cmd := exec.Command("gh", "api", "rate_limit")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to check rate limit: %w", err)
	}

	// Parse JSON response for rate limit
	var result struct {
		Rate struct {
			Remaining int    `json:"remaining"`
			Limit     int    `json:"limit"`
			Reset     int64  `json:"reset"`
		} `json:"rate"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("failed to parse rate limit: %w", err)
	}

	return &RateLimit{
		Remaining: result.Rate.Remaining,
		Limit:     result.Rate.Limit,
		Reset:     time.Unix(result.Rate.Reset, 0),
	}, nil
}

// WaitForRateLimit waits until the rate limit resets if we're close to exhaustion.
func WaitForRateLimit(minRemaining int) error {
	for {
		rl, err := CheckRateLimit()
		if err != nil {
			return err
		}
		if rl.Remaining >= minRemaining {
			return nil
		}

		wait := time.Until(rl.Reset) + time.Second
		fmt.Printf("Rate limited. Waiting %v for reset...\n", wait.Round(time.Second))
		time.Sleep(wait)
	}
}

// CloneRepo performs a shallow clone of a repository.
func CloneRepo(org, repo, token, dest string) error {
	url := fmt.Sprintf("https://%s@github.com/%s/%s.git", token, org, repo)
	cmd := exec.Command("git", "clone", "--depth", "1", "--filter=blob:none", url, dest)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to clone %s/%s: %w", org, repo, err)
	}
	return nil
}

// Finding represents a security finding from abom.
type Finding struct {
	RuleID   string
	Level    string
	Message  string
	Location string
}

// ParseAbomOutput parses the output of `abom scan` command.
func ParseAbomOutput(output string) []Finding {
	var findings []Finding
	// Pattern: COMPROMISED action (ABOM-YYYY-NNN)
	re := regexp.MustCompile(`(?i)(COMPROMISED|VULNERABLE).*\(?(ABOM-\d+-\d+)\)?`)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			findings = append(findings, Finding{
				RuleID:  matches[2],
				Level:   "error",
				Message: strings.TrimSpace(line),
			})
		}
	}
	return findings
}
