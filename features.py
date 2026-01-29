"""
UEBA Feature Engineering Pipeline.

Per-user behavioral features extracted from normalized auth events:
  1. Login hour entropy       — uniformity of login times (high = unusual spread)
  2. Geo variance             — geographic dispersion of login locations
  3. Device churn             — rate of new/unique devices over time
  4. Failure ratio            — proportion of failed auth attempts
  5. Unique countries         — number of distinct countries
  6. Unique IPs              — number of distinct source IPs
  7. Off-hours ratio          — proportion of logins outside 07:00-19:00
  8. Avg events per day       — activity volume
  9. Geo velocity             — max km/h between consecutive logins (impossible travel)
  10. MFA absence ratio       — proportion of logins without MFA
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np

from models import AuthEvent


FEATURE_NAMES = [
    "login_hour_entropy",
    "geo_variance_km",
    "device_churn_rate",
    "failure_ratio",
    "unique_countries",
    "unique_ips",
    "off_hours_ratio",
    "avg_events_per_day",
    "geo_velocity_max_kmh",
    "mfa_absence_ratio",
]


@dataclass
class UserFeatures:
    username: str
    login_hour_entropy: float = 0.0
    geo_variance_km: float = 0.0
    device_churn_rate: float = 0.0
    failure_ratio: float = 0.0
    unique_countries: int = 0
    unique_ips: int = 0
    off_hours_ratio: float = 0.0
    avg_events_per_day: float = 0.0
    geo_velocity_max_kmh: float = 0.0
    mfa_absence_ratio: float = 0.0
    event_count: int = 0

    def to_vector(self) -> list[float]:
        return [
            self.login_hour_entropy,
            self.geo_variance_km,
            self.device_churn_rate,
            self.failure_ratio,
            float(self.unique_countries),
            float(self.unique_ips),
            self.off_hours_ratio,
            self.avg_events_per_day,
            self.geo_velocity_max_kmh,
            self.mfa_absence_ratio,
        ]

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "event_count": self.event_count,
            **{name: val for name, val in zip(FEATURE_NAMES, self.to_vector())},
        }


# ---------------------------------------------------------------------------
# Feature computation helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(counts: list[int]) -> float:
    """Shannon entropy in bits over a frequency distribution."""
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return -sum(p * math.log2(p) for p in probs)


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on Earth."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _geo_variance(events: list[AuthEvent]) -> float:
    """Mean distance (km) from centroid of all login locations."""
    lats = [e.geo_lat for e in events if e.geo_lat != 0.0]
    lons = [e.geo_lon for e in events if e.geo_lon != 0.0]
    if len(lats) < 2:
        return 0.0
    clat = sum(lats) / len(lats)
    clon = sum(lons) / len(lons)
    distances = [_haversine_km(clat, clon, lat, lon) for lat, lon in zip(lats, lons)]
    return float(np.std(distances))


def _max_geo_velocity(events: list[AuthEvent]) -> float:
    """Maximum travel speed (km/h) between consecutive logins — impossible travel detector."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    max_v = 0.0
    for i in range(1, len(sorted_events)):
        prev, curr = sorted_events[i - 1], sorted_events[i]
        if prev.geo_lat == 0.0 or curr.geo_lat == 0.0:
            continue
        dist = _haversine_km(prev.geo_lat, prev.geo_lon, curr.geo_lat, curr.geo_lon)
        dt_hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600.0
        if dt_hours > 0 and dist > 10:  # ignore same-location noise
            v = dist / dt_hours
            max_v = max(max_v, v)
    return max_v


def _device_churn(events: list[AuthEvent]) -> float:
    """
    Device churn rate: unique devices in the last 25% of the time window
    divided by unique devices in the first 75%.
    A ratio >> 1 indicates many new devices appearing recently.
    """
    sorted_events = sorted(events, key=lambda e: e.timestamp)
    if len(sorted_events) < 4:
        return 0.0
    split = int(len(sorted_events) * 0.75)
    early_devices = set(e.device_id for e in sorted_events[:split])
    late_devices = set(e.device_id for e in sorted_events[split:])
    new_devices = late_devices - early_devices
    if not early_devices:
        return float(len(new_devices))
    return len(new_devices) / max(len(early_devices), 1)


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def extract_features(events: list[AuthEvent]) -> list[UserFeatures]:
    """Group events by user and compute behavioral feature vectors."""
    by_user: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in events:
        by_user[e.username].append(e)

    results = []
    for username, user_events in sorted(by_user.items()):
        if len(user_events) < 3:
            continue

        # Hour entropy
        hour_counts = [0] * 24
        for e in user_events:
            hour_counts[e.timestamp.hour] += 1
        hour_entropy = _shannon_entropy(hour_counts)

        # Geo variance
        geo_var = _geo_variance(user_events)

        # Device churn
        dev_churn = _device_churn(user_events)

        # Failure ratio
        failures = sum(1 for e in user_events if e.result.value == "failure")
        fail_ratio = failures / len(user_events)

        # Unique countries
        countries = set(e.geo_country for e in user_events if e.geo_country != "unknown")

        # Unique IPs
        ips = set(e.source_ip for e in user_events)

        # Off-hours ratio (before 7am or after 7pm)
        off_hours = sum(1 for e in user_events if e.timestamp.hour < 7 or e.timestamp.hour >= 19)
        off_ratio = off_hours / len(user_events)

        # Avg events per day
        timestamps = [e.timestamp for e in user_events]
        day_span = (max(timestamps) - min(timestamps)).days + 1
        avg_epd = len(user_events) / max(day_span, 1)

        # Geo velocity
        max_vel = _max_geo_velocity(user_events)

        # MFA absence
        no_mfa = sum(1 for e in user_events if not e.mfa_used)
        mfa_absence = no_mfa / len(user_events)

        results.append(UserFeatures(
            username=username,
            login_hour_entropy=round(hour_entropy, 4),
            geo_variance_km=round(geo_var, 2),
            device_churn_rate=round(dev_churn, 4),
            failure_ratio=round(fail_ratio, 4),
            unique_countries=len(countries),
            unique_ips=len(ips),
            off_hours_ratio=round(off_ratio, 4),
            avg_events_per_day=round(avg_epd, 2),
            geo_velocity_max_kmh=round(max_vel, 2),
            mfa_absence_ratio=round(mfa_absence, 4),
            event_count=len(user_events),
        ))

    return results
