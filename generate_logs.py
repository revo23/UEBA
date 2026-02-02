"""
Synthetic auth log generator for UEBA testing.

Generates realistic Windows / Okta / AWS / Webapp / Linux auth events with:
- Normal users: consistent hours, stable geos, few devices
- Anomalous users: odd hours, geo-hopping, device churn, high failure rates
"""

from __future__ import annotations

import json
import random
import math
from datetime import datetime, timedelta
from pathlib import Path

from models import LogSource

# ---------------------------------------------------------------------------
# Geo profiles
# ---------------------------------------------------------------------------

GEOS = {
    "us_east":    ("US", "New York",    40.7128, -74.0060),
    "us_west":    ("US", "San Francisco", 37.7749, -122.4194),
    "uk":         ("GB", "London",      51.5074,  -0.1278),
    "de":         ("DE", "Berlin",      52.5200,  13.4050),
    "jp":         ("JP", "Tokyo",       35.6762, 139.6503),
    "br":         ("BR", "São Paulo",  -23.5505, -46.6333),
    "au":         ("AU", "Sydney",     -33.8688, 151.2093),
    "sg":         ("SG", "Singapore",    1.3521, 103.8198),
    "ru":         ("RU", "Moscow",      55.7558,  37.6173),
    "cn":         ("CN", "Beijing",     39.9042, 116.4074),
}

DEVICES = [f"device-{i:04d}" for i in range(200)]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "aws-cli/2.13.0 Python/3.11.4",
    "Okta-Browser-Plugin/6.21.0",
]

WEBAPP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.2",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
]

WEBAPP_EVENT_TYPES = ["login", "login", "login", "login", "logout", "logout", "password_reset", "session_expired", "account_lockout"]
WEBAPP_APP_NAMES = ["portal", "dashboard", "admin", "api"]
WEBAPP_REQUEST_PATHS = {
    "login": "/auth/login",
    "logout": "/auth/logout",
    "password_reset": "/auth/password-reset",
    "session_expired": "/auth/session",
    "account_lockout": "/auth/login",
}
WEBAPP_HTTP_METHODS = {
    "login": "POST",
    "logout": "POST",
    "password_reset": "POST",
    "session_expired": "GET",
    "account_lockout": "POST",
}

LINUX_AUTH_SERVICES = ["ssh", "ssh", "ssh", "sudo", "sudo", "su", "pam"]
LINUX_AUTH_METHODS = ["password", "publickey", "keyboard-interactive"]
LINUX_HOSTNAMES = [
    "web-srv-01", "web-srv-02", "db-srv-01", "db-srv-02",
    "app-srv-01", "app-srv-02", "mail-srv-01", "ci-srv-01",
]
LINUX_SUDO_COMMANDS = [
    "/bin/bash", "/usr/bin/apt", "/usr/bin/systemctl",
    "/usr/bin/journalctl", "/usr/sbin/reboot", "/usr/bin/docker",
    "/usr/bin/cat /etc/shadow", "/usr/bin/vi /etc/hosts",
]
LINUX_TTY = ["pts/0", "pts/1", "pts/2", "ttyS0"]
LINUX_USER_AGENTS = [
    "OpenSSH_9.6", "OpenSSH_9.2p1", "OpenSSH_8.9p1",
    "PuTTY_Release_0.80", "libssh2/1.11.0",
]


def _pick_geo(allowed: list[str]) -> tuple[str, str, float, float]:
    return GEOS[random.choice(allowed)]


# ---------------------------------------------------------------------------
# User profiles
# ---------------------------------------------------------------------------

class UserProfile:
    def __init__(
        self,
        username: str,
        sources: list[str],
        home_geos: list[str],
        num_devices: int,
        work_hours: tuple[int, int],
        failure_rate: float,
        is_anomalous: bool = False,
        anomaly_start_day: int | None = None,
        anomaly_traits: list[str] | None = None,
    ):
        self.username = username
        self.sources = sources
        self.home_geos = home_geos
        self.devices = random.sample(DEVICES, min(num_devices, len(DEVICES)))
        self.work_hours = work_hours
        self.failure_rate = failure_rate
        self.is_anomalous = is_anomalous
        self.anomaly_start_day = anomaly_start_day
        self.anomaly_traits = anomaly_traits or []


def build_normal_users(n: int = 20) -> list[UserProfile]:
    users = []
    for i in range(n):
        geo_keys = list(GEOS.keys())
        home = random.sample(geo_keys, k=random.randint(1, 2))
        sources = random.sample(["windows", "okta", "aws", "webapp", "linux"], k=random.randint(1, 5))
        users.append(UserProfile(
            username=f"user_{i:03d}",
            sources=sources,
            home_geos=home,
            num_devices=random.randint(1, 3),
            work_hours=(8, 18),
            failure_rate=0.02,
        ))
    return users


def build_anomalous_users(n: int = 5) -> list[UserProfile]:
    """
    Anomalous users that exhibit one or more suspicious traits
    starting partway through the observation window.
    """
    trait_combos = [
        ["odd_hours", "geo_hop"],
        ["device_churn", "high_failure"],
        ["odd_hours", "device_churn", "geo_hop"],
        ["geo_hop", "high_failure"],
        ["odd_hours", "geo_hop", "device_churn", "high_failure"],
    ]
    users = []
    for i in range(n):
        geo_keys = list(GEOS.keys())
        home = random.sample(geo_keys, k=1)
        sources = random.sample(["windows", "okta", "aws", "webapp", "linux"], k=random.randint(2, 5))
        traits = trait_combos[i % len(trait_combos)]
        users.append(UserProfile(
            username=f"anomaly_{i:03d}",
            sources=sources,
            home_geos=home,
            num_devices=2,
            work_hours=(9, 17),
            failure_rate=0.03,
            is_anomalous=True,
            anomaly_start_day=random.randint(15, 25),
            anomaly_traits=traits,
        ))
    return users


# ---------------------------------------------------------------------------
# Event generation
# ---------------------------------------------------------------------------

def _gen_event(
    user: UserProfile,
    ts: datetime,
    day_index: int,
) -> dict:
    in_anomaly_phase = (
        user.is_anomalous
        and user.anomaly_start_day is not None
        and day_index >= user.anomaly_start_day
    )

    # Hour selection
    if in_anomaly_phase and "odd_hours" in user.anomaly_traits:
        hour = random.choice([0, 1, 2, 3, 4, 22, 23])
    else:
        hour = random.randint(user.work_hours[0], user.work_hours[1])
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts.replace(hour=hour, minute=minute, second=second)

    # Geo selection
    if in_anomaly_phase and "geo_hop" in user.anomaly_traits:
        all_geos = list(GEOS.keys())
        geo = _pick_geo(all_geos)
    else:
        geo = _pick_geo(user.home_geos)

    # Device selection
    if in_anomaly_phase and "device_churn" in user.anomaly_traits:
        device = random.choice(DEVICES)  # any device
    else:
        device = random.choice(user.devices)

    # Failure rate
    fail_rate = user.failure_rate
    if in_anomaly_phase and "high_failure" in user.anomaly_traits:
        fail_rate = 0.35
    result = "failure" if random.random() < fail_rate else "success"

    source = random.choice(user.sources)
    ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    event = {
        "timestamp": ts.isoformat() + "Z",
        "username": user.username,
        "source": source,
        "result": result,
        "source_ip": ip,
        "geo_country": geo[0],
        "geo_city": geo[1],
        "geo_lat": geo[2],
        "geo_lon": geo[3],
        "device_id": device if source not in ("webapp", "linux") else (f"fp-{random.randint(0x1000, 0xffff):04x}" if source == "webapp" else random.choice(LINUX_HOSTNAMES)),
        "device_type": {"windows": "workstation", "webapp": "browser", "linux": "server"}.get(source, "browser"),
        "user_agent": random.choice(LINUX_USER_AGENTS if source == "linux" else (WEBAPP_USER_AGENTS if source == "webapp" else USER_AGENTS)),
        "session_id": f"sess-{random.randint(100000, 999999)}",
        "mfa_used": random.random() < 0.6,
    }

    if source == "webapp":
        event_type = random.choice(WEBAPP_EVENT_TYPES)
        # Override result for account_lockout events
        if event_type == "account_lockout":
            event["result"] = "locked_out"
        event["event_type"] = event_type
        event["app_name"] = random.choice(WEBAPP_APP_NAMES)
        event["http_method"] = WEBAPP_HTTP_METHODS[event_type]
        event["request_path"] = WEBAPP_REQUEST_PATHS[event_type]
        r = event["result"]
        if r == "success":
            event["status_code"] = 200
        elif r == "failure":
            event["status_code"] = 401
        elif r == "locked_out":
            event["status_code"] = 423
        else:
            event["status_code"] = 200

    elif source == "linux":
        auth_service = random.choice(LINUX_AUTH_SERVICES)
        hostname = random.choice(LINUX_HOSTNAMES)
        event["auth_service"] = auth_service
        event["hostname"] = hostname
        event["device_id"] = hostname
        event["pid"] = random.randint(1000, 65535)
        event["tty"] = random.choice(LINUX_TTY)

        if auth_service == "ssh":
            auth_method = random.choice(LINUX_AUTH_METHODS)
            event["auth_method"] = auth_method
            event["port"] = 22
            event["protocol"] = "ssh2"
        elif auth_service == "sudo":
            event["target_user"] = "root"
            event["command"] = random.choice(LINUX_SUDO_COMMANDS)
        elif auth_service == "su":
            event["target_user"] = random.choice(["root", "www-data", "postgres"])
        elif auth_service == "pam":
            # Override result for PAM lockout scenario
            if random.random() < 0.1:
                event["result"] = "locked_out"

    return event


def generate_dataset(
    days: int = 30,
    events_per_user_per_day: tuple[int, int] = (3, 12),
    n_normal: int = 20,
    n_anomalous: int = 5,
    seed: int = 42,
) -> tuple[list[dict], list[str]]:
    """
    Returns (events, anomalous_usernames).
    """
    random.seed(seed)
    start_date = datetime(2025, 1, 1)

    normals = build_normal_users(n_normal)
    anomalies = build_anomalous_users(n_anomalous)
    all_users = normals + anomalies

    events = []
    for day in range(days):
        current_date = start_date + timedelta(days=day)
        for user in all_users:
            n_events = random.randint(*events_per_user_per_day)
            for _ in range(n_events):
                events.append(_gen_event(user, current_date, day))

    random.shuffle(events)
    anomalous_names = [u.username for u in anomalies]
    return events, anomalous_names


def save_dataset(output_dir: Path, events: list[dict], anomalous_users: list[str]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Split by source type
    by_source: dict[str, list[dict]] = {"windows": [], "okta": [], "aws": [], "webapp": [], "linux": []}
    for e in events:
        by_source.setdefault(e["source"], []).append(e)

    for source, source_events in by_source.items():
        p = output_dir / f"{source}_auth_logs.json"
        p.write_text(json.dumps(source_events, indent=2))

    # Also save combined
    combined = output_dir / "all_auth_logs.json"
    combined.write_text(json.dumps(events, indent=2))

    # Ground truth
    gt = output_dir / "ground_truth.json"
    gt.write_text(json.dumps({"anomalous_users": anomalous_users}, indent=2))

    print(f"Generated {len(events)} events for {output_dir}")
    for src, evts in by_source.items():
        print(f"  {src}: {len(evts)} events")
    print(f"  Anomalous users: {anomalous_users}")


if __name__ == "__main__":
    events, anomalous = generate_dataset()
    save_dataset(Path("sample_data"), events, anomalous)
