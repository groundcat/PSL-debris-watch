# PSL Debris Watch

Daily monitor for Public Suffix List (PSL) domains to detect state changes and anomalies.

## Overview

This tool runs daily via GitHub Actions to check domains listed in the extended PSL JSON. It manages GitHub Issues in this repository to report:
- Domain Expirations
- Registry Holds
- New Registrations (of existing PSL domains)
- DNS Errors (NXDOMAIN, SERVFAIL)
- Missing `_psl` TXT records (for private section domains)

## Setup

1. **Requirements**: Python 3.12+
2. **Installation**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Usage**:
   - The script is designed to run in GitHub Actions.
   - It requires `GITHUB_TOKEN` and `GITHUB_REPOSITORY` environment variables.
   
   To run locally (dry-run/debugging requires valid GH token):
   ```bash
   export GITHUB_TOKEN="your_token"
   export GITHUB_REPOSITORY="your/repo"
   python src/monitor.py
   ```

## Architecture

- `src/monitor.py`: Main entry point.
- `src/dns_checker.py`: Handles DNS queries using `dnspython`.
- `src/gh_manager.py`: Abstraction for GitHub API interactions using `PyGithub`.
- `data/monitor_state.json`: Persisted state (committed to repo) to track "yesterday's" status.

## License

[MIT](LICENSE)
