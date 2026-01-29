UEBA from auth logs

Input: Windows / Okta / AWS auth logs

Features: login hour entropy, geo variance, device churn

Model: Isolation Forest

Output: ranked anomalies + explanation


# Full demo with synthetic data
python main.py demo

# Analyze your own logs
python main.py analyze --input /path/to/auth_logs.json --source auto

# Generate custom synthetic data
python main.py generate --days 60 --normal-users 50 --anomalous-users 10
