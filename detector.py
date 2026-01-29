"""
UEBA Anomaly Detector — Isolation Forest with ranked output and explanations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import UserFeatures, FEATURE_NAMES


@dataclass
class AnomalyResult:
    username: str
    anomaly_score: float          # higher = more anomalous (negated IF score)
    is_anomaly: bool
    rank: int = 0
    feature_contributions: dict[str, float] = field(default_factory=dict)
    top_reasons: list[str] = field(default_factory=list)
    raw_features: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rank": self.rank,
            "username": self.username,
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": bool(self.is_anomaly),
            "top_reasons": self.top_reasons,
            "feature_contributions": {
                k: round(v, 4) for k, v in self.feature_contributions.items()
            },
            "raw_features": self.raw_features,
        }


# ---------------------------------------------------------------------------
# Explanation engine
# ---------------------------------------------------------------------------

# Human-readable descriptions for each feature when it's elevated
FEATURE_EXPLANATIONS = {
    "login_hour_entropy": "Login times are unusually spread across all hours (high entropy) — may indicate automated access or compromised credentials used across time zones",
    "geo_variance_km": "Login locations are geographically dispersed — unusual for a single user, may indicate credential sharing or compromise",
    "device_churn_rate": "Many new/unseen devices appeared recently — possible credential stuffing or account takeover",
    "failure_ratio": "High ratio of failed authentication attempts — may indicate brute-force or credential spraying",
    "unique_countries": "Logins from an unusually high number of distinct countries — impossible travel or proxy/VPN abuse",
    "unique_ips": "Logins from many unique IP addresses — possible credential sharing or botnet activity",
    "off_hours_ratio": "High proportion of logins outside business hours (before 7am / after 7pm) — may indicate unauthorized access",
    "avg_events_per_day": "Unusually high login volume per day — possible automated access or service account abuse",
    "geo_velocity_max_kmh": "Impossible travel detected — consecutive logins from distant locations in a short time span",
    "mfa_absence_ratio": "High proportion of logins without MFA — may indicate MFA bypass or legacy auth protocol abuse",
}


def _compute_feature_contributions(
    user_vec: np.ndarray,
    mean_vec: np.ndarray,
    std_vec: np.ndarray,
) -> dict[str, float]:
    """
    Compute per-feature z-scores as a proxy for how much each feature
    contributes to the anomaly score. Higher z-score = more unusual.
    """
    z_scores = {}
    for i, name in enumerate(FEATURE_NAMES):
        if std_vec[i] > 0:
            z = (user_vec[i] - mean_vec[i]) / std_vec[i]
        else:
            z = 0.0
        z_scores[name] = abs(z)
    return z_scores


def _build_explanations(
    contributions: dict[str, float],
    raw_features: dict[str, float],
    top_n: int = 3,
) -> list[str]:
    """
    Build human-readable explanation strings for the top contributing features.
    """
    sorted_feats = sorted(contributions.items(), key=lambda x: x[1], reverse=True)
    reasons = []
    for feat_name, z_score in sorted_feats[:top_n]:
        if z_score < 1.0:
            continue
        val = raw_features.get(feat_name, 0)
        base = FEATURE_EXPLANATIONS.get(feat_name, feat_name)
        reasons.append(f"[z={z_score:.1f}] {feat_name}={val:.2f} — {base}")
    return reasons


# ---------------------------------------------------------------------------
# Isolation Forest detector
# ---------------------------------------------------------------------------

class UEBADetector:
    def __init__(
        self,
        contamination: float = 0.15,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._feature_matrix: Optional[np.ndarray] = None

    def fit_predict(self, user_features: list[UserFeatures]) -> list[AnomalyResult]:
        """
        Fit Isolation Forest on user feature vectors and return ranked anomalies.
        """
        if not user_features:
            return []

        # Build feature matrix
        X = np.array([uf.to_vector() for uf in user_features])
        self._feature_matrix = X

        # Standardize
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Fit Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        # score_samples: lower (more negative) = more anomalous
        scores = self.model.score_samples(X_scaled)
        predictions = self.model.predict(X_scaled)  # -1 = anomaly, 1 = normal

        # Compute stats for explanation
        mean_vec = X.mean(axis=0)
        std_vec = X.std(axis=0)

        # Build results
        results: list[AnomalyResult] = []
        for i, uf in enumerate(user_features):
            anomaly_score = -scores[i]  # negate so higher = more anomalous
            is_anom = predictions[i] == -1

            raw_feats = {name: val for name, val in zip(FEATURE_NAMES, X[i])}
            contributions = _compute_feature_contributions(X[i], mean_vec, std_vec)
            reasons = _build_explanations(contributions, raw_feats)

            results.append(AnomalyResult(
                username=uf.username,
                anomaly_score=anomaly_score,
                is_anomaly=is_anom,
                feature_contributions=contributions,
                top_reasons=reasons,
                raw_features=raw_feats,
            ))

        # Rank by anomaly score descending
        results.sort(key=lambda r: r.anomaly_score, reverse=True)
        for rank, r in enumerate(results, 1):
            r.rank = rank

        return results
