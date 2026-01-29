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
- Top signals: device churn (z=3.4), off-hours logins (z=3.2), geo dispersion (z=2.6), impossible travel (z=2.2)
