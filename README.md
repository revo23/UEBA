#  User and Entity Behavior Analytics from authentication logs

Input: Windows / Okta / AWS / Webapp / Linux auth logs

Features: login hour entropy, geo variance, device churn

Model: Isolation Forest

Output: ranked anomalies + explanation

Results saved to sample_data/ueba_results.json


# Full demo with synthetic data
python3 -m venv venv

source venv/bin/activate

pip install numpy pandas scikit-learn matplotlib

python main.py demo

# Analyze your own logs (supports: windows, okta, aws, webapp, linux, or auto-detect)
python main.py analyze --input /path/to/auth_logs.json --source auto

# Generate custom synthetic data
python main.py generate --days 60 --normal-users 50 --anomalous-users 10



# Features Extracted (per user)
| Feature                 | What it captures                                           |
|-------------------------|------------------------------------------------------------|
| login_hour_entropy       | Uniformity of login times across hours (high = suspicious spread) |
| geo_variance_km          | Std dev of distances from centroid of login locations     |
| device_churn_rate        | Ratio of new devices in recent 25% vs. established devices |
| failure_ratio            | Failed auth / total auth attempts                          |
| unique_countries         | Distinct countries seen in logins                          |
| unique_ips               | Distinct source IPs                                        |
| off_hours_ratio          | Logins outside 07:00-19:00                                 |
| avg_events_per_day       | Activity volume                                            |
| geo_velocity_max_kmh     | Impossible travel — max km/h between consecutive logins   |
| mfa_absence_ratio        | Logins without MFA                                        |


# Demo Results
- 25 users analyzed (20 normal, 5 injected anomalies)
- 4/5 true anomalies detected, 0 false positives
- 100% precision, 80% recall, 88.9% F1
  - Precision: Of the 4 users the model flagged as anomalous, all 4 were genuinely anomalous. Zero false positives. In practice this means: every alert the system fires is worth investigating, no analyst time wasted on false alarms.
  - Recall: Of the 5 truly anomalous users, the model caught 4. It missed anomaly_001 (a false negative). That user's anomaly traits (device_churn + high_failure) weren't extreme enough to separate it from the normal population at the current contamination threshold.
  - F1: The harmonic mean of precision and recall. It penalizes imbalance — if either metric is low, F1 drops. 88.9% reflects strong precision slightly offset by the one missed user.
- Top signals: device churn (z=4.9), impossible travel (z=4.9), off-hours logins (z=3.8), failure ratio (z=3.1)
  - A z-score (also called a standard score) measures how many standard deviations a data point is from the mean.

Formula: z = (x - μ) / σ  
Where:  
x = individual value  
μ = mean of the dataset  
σ = standard deviation  

Interpretation:  

z = 0: value is exactly at the mean  
z = 1: value is 1 standard deviation above the mean  
z = -1: value is 1 standard deviation below the mean  
z > 2 or z < -2: typically considered unusual (about 5% of data)  
z > 3 or z < -3: very unusual (about 0.3% of data)  

# Security Review - Static Application Security Testing (SAST) and Software Composition Analysis (SCA) 

Automated security reviews in Claude Code help developers catch vulnerabilities before they reach production. These features check for common security issues including SQL injection risks, cross-site scripting (XSS) vulnerabilities, authentication flaws, insecure data handling, and dependency vulnerabilities.

You can use security reviews in two ways: through the /security-review command for on-demand checks in your terminal, or through GitHub Actions for automatic review of pull requests.

## Security Review Results

**No HIGH or MEDIUM severity vulnerabilities found.**

### Scope

All source files were reviewed:
- `main.py` - CLI entry point and orchestration
- `models.py` - Data models and log parsers (Windows, Okta, AWS, Webapp, Linux)
- `features.py` - Feature extraction pipeline
- `detector.py` - Anomaly detection engine
- `generate_logs.py` - Synthetic test data generator (all 5 log sources)

### Assessment

The codebase has a limited attack surface:
- No web server, database, or network-facing components
- No use of dangerous deserialization (`pickle`, `yaml.load`, `marshal`)
- No `eval()`, `exec()`, `subprocess`, or `os.system` calls
- No cryptographic operations or authentication logic
- No hardcoded secrets, API keys, or credentials
- All file path inputs come from CLI arguments (trusted values)
- JSON parsing uses only `json.loads` (safe)

## GitHub Actions - Automated Security Review on Pull Requests

This project uses a GitHub Actions workflow to automatically run a security review on every pull request. The workflow leverages the [Claude Code Security Review](https://github.com/anthropics/claude-code-security-review) action to perform Static Application Security Testing (SAST) and Software Composition Analysis (SCA).

### How It Works

1. **Trigger**: The workflow runs automatically when a pull request is opened or updated against any branch.
2. **Checkout**: The action checks out the PR's head commit with a fetch depth of 2 (to allow diff-based analysis).
3. **Security Scan**: The `anthropics/claude-code-security-review@main` action analyzes the changed files for vulnerabilities including:
   - SQL injection, XSS, and other OWASP Top 10 risks
   - Insecure deserialization and unsafe function usage
   - Hardcoded secrets or credentials
   - Dependency vulnerabilities
4. **PR Comment**: Results are posted directly as a comment on the pull request (`comment-pr: true`), giving reviewers immediate visibility into any findings.

### Workflow Configuration

The workflow is defined in `.github/workflows/security.yml`:

```yaml
name: Security Review

permissions:
  pull-requests: write
  contents: read

on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 2

      - uses: anthropics/claude-code-security-review@main
        with:
          comment-pr: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

### Setup Requirements

- **`CLAUDE_API_KEY`**: Must be stored as a repository secret (`Settings > Secrets and variables > Actions`). This key authenticates with the Anthropic API to power the security analysis.
- **Permissions**: The workflow requires `pull-requests: write` to post review comments and `contents: read` to access the repository code.

### Testing the Workflow

To test the security review workflow:

1. Create a feature branch: `git checkout -b feature/your-change`
2. Make changes and push: `git push -u origin feature/your-change`
3. Open a pull request on GitHub
4. The security review will run automatically and post findings as a PR comment
