# ghbom

GitHub Actions Bill of Materials — scan all repos in an org for compromised actions.

ghbom combines the power of [abom](https://github.com/JulietSecurity/abom) (GitHub Actions security analysis) with org-wide scanning into a single self-contained tool. No external dependencies for the scanning logic.

## Features

- Scan all repos in a GitHub organization for compromised actions
- Embedded abom engine — no external dependency required
- Recursive resolution of composite actions and reusable workflows
- Tool wrapper detection (finds actions that silently embed Trivy, Grype, Snyk, etc.)
- Parallel scanning with configurable concurrency
- Multiple output formats (text, JSON, SARIF)
- Rate limit awareness via `gh` CLI
- Progress reporting

## Installation

### Homebrew

```bash
brew install wplatnick/tap/ghbom
```

### Build from source

```bash
git clone https://github.com/Wrentastic/ghbom
cd ghbom
go install
```

## Usage

```bash
# Scan all repos in an organization
ghbom --org my-org

# Scan with higher concurrency
ghbom --org my-org --concurrency 10

# Output to JSON file
ghbom --org my-org --format json --output results.json

# Generate SARIF for GitHub Code Scanning
ghbom --org my-org --format sarif --output results.sarif

# Skip repos without workflow files
ghbom --org my-org --skip-existing
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--org` | (required) | GitHub organization name |
| `--concurrency` | 5 | Number of parallel scans |
| `--format` | text | Output format: text, json, sarif |
| `--output` | stdout | Output file path |
| `--skip-existing` | false | Skip repos without workflow files |

## SARIF Integration

ghbom outputs SARIF 2.1.0, uploadable to GitHub Security Dashboard:

```bash
ghbom --org my-org --format sarif --output ghbom.sarif
gh code-scanning upload --sarif-file ghbom.sarif --repo my-org/my-repo
```

## What It Detects

ghbom uses Juliet Security's advisory database to detect:

- Known compromised actions (CVE-affected versions)
- Actions that embed vulnerable tools transitively
- Actions pulling from known-malicious sources

Currently detects ABOM-2026-001 (CVE-2026-33634, the Trivy supply chain compromise) and similar patterns.

## How It Works

1. Lists all repositories in the org using `gh repo list`
2. For each repo with workflow files, shallow clones it
3. Parses workflow YAML files and resolves all action references
4. Recursively resolves composite actions and reusable workflows
5. Checks each action against Juliet Security's advisory database
6. Reports findings with file location, action version, and advisory ID
7. Cleans up temporary clone directories

## Prerequisites

- Go 1.26+
- `gh` CLI authenticated (`gh auth login`)
- `git`

## Architecture

ghbom embeds abom's core packages directly:

- `internal/abom/pkg/model` — Action and workflow data structures
- `internal/abom/pkg/parser` — Workflow YAML parsing
- `internal/abom/pkg/resolver` — Transitive action resolution
- `internal/abom/pkg/advisory` — Juliet Security advisory database

This means ghbom ships the complete scanning engine — no external binary required.

## License

MIT
