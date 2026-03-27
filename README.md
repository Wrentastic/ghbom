# ghbom

GitHub Actions Bill of Materials — scan all repos in an org for compromised actions.

## Description

ghbom is a CLI tool that scans all repositories in a GitHub organization for known compromised or vulnerable GitHub Actions. It uses [abom](https://github.com/chainguard-dev/abom) to detect malicious actions in workflow files.

## Features

- Scan all repos in a GitHub organization for compromised actions
- Parallel scanning with configurable concurrency
- Multiple output formats (text, JSON, SARIF)
- Rate limit awareness
- Progress reporting

## Installation

### Homebrew

```bash
brew tap wplatnick/tap
brew install ghbom
```

### Binary

Download the latest release for your platform from the releases page and install manually.

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

ghbom can output results in SARIF format for integration with GitHub Code Scanning.

```bash
ghbom --org my-org --format sarif --output ghbom.sarif
```

Upload to GitHub using the `gh code-search` or the Security tab in your repository settings.

## How It Works

1. Lists all repositories in the specified organization using `gh repo list`
2. For each repository, checks if it has GitHub Actions workflows
3. Shallow clones the repository to a temporary directory
4. Runs `abom scan --check` to detect compromised actions
5. Parses and formats the results
6. Cleans up temporary clone directories

## Prerequisites

- Go 1.21+
- `gh` CLI authenticated (`gh auth login`)
- `git`
- `abom` (install from https://github.com/chainguard-dev/abom)

## License

MIT
