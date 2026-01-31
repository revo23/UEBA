#  User and Entity Behavior Analytics from authentication logs

Input: Windows / Okta / AWS auth logs

Features: login hour entropy, geo variance, device churn

Model: Isolation Forest

Output: ranked anomalies + explanation

Results saved to sample_data/ueba_results.json


# Full demo with synthetic data
python3 -m venv venv

source venv/bin/activate

pip install numpy pandas scikit-learn matplotlib

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
  - Precision: Of the 4 users the model flagged as anomalous, all 4 were genuinely anomalous. Zero false positives. In practice this means: every alert the system fires is worth investigating, no analyst time wasted on false alarms.
  - Recall: Of the 5 truly anomalous users, the model caught 4. It missed anomaly_001 (a false negative). That user's anomaly traits (device_churn + high_failure) weren't extreme enough to separate it from the normal population at the current contamination threshold.
  - F1: The harmonic mean of precision and recall. It penalizes imbalance — if either metric is low, F1 drops. 88.9% reflects strong precision slightly offset by the one missed user.
- Top signals: device churn (z=3.4), off-hours logins (z=3.2), geo dispersion (z=2.6), impossible travel (z=2.2)
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

