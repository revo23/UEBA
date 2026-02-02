"""
UEBA Data Models — Normalized auth event schema for Windows, Okta, AWS, Webapp, and Linux logs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


class LogSource(str, Enum):
    WINDOWS = "windows"
    OKTA = "okta"
    AWS = "aws"
    WEBAPP = "webapp"
    LINUX = "linux"


class AuthResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    MFA_CHALLENGE = "mfa_challenge"
    LOCKED_OUT = "locked_out"


@dataclass
class AuthEvent:
    """Normalized authentication event across all log sources."""

    timestamp: datetime
    username: str
    source: LogSource
    result: AuthResult
    source_ip: str
    geo_country: str = "unknown"
    geo_city: str = "unknown"
    geo_lat: float = 0.0
    geo_lon: float = 0.0
    device_id: str = "unknown"
    device_type: str = "unknown"
    user_agent: str = ""
    session_id: str = ""
    mfa_used: bool = False
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["source"] = self.source.value
        d["result"] = self.result.value
        return d


# ---------------------------------------------------------------------------
# Parsers: raw log dict → AuthEvent
# ---------------------------------------------------------------------------

def _parse_result(raw: dict) -> AuthResult:
    """Fallback result parser for synthetic / generic logs."""
    r = raw.get("result", "").lower()
    if r == "success":
        return AuthResult.SUCCESS
    elif r == "failure":
        return AuthResult.FAILURE
    elif r == "mfa_challenge":
        return AuthResult.MFA_CHALLENGE
    elif r == "locked_out":
        return AuthResult.LOCKED_OUT
    return AuthResult.FAILURE


def parse_windows_event(raw: dict) -> AuthEvent:
    """Parse a Windows Security Event Log (Event ID 4624/4625)."""
    event_id = raw.get("EventID", raw.get("event_id", None))
    if event_id is not None:
        result = AuthResult.SUCCESS if int(event_id) == 4624 else AuthResult.FAILURE
    else:
        result = _parse_result(raw)

    ts_raw = raw.get("TimeCreated", raw.get("timestamp", ""))
    ts = _parse_timestamp(ts_raw)

    return AuthEvent(
        timestamp=ts,
        username=raw.get("TargetUserName", raw.get("username", "unknown")),
        source=LogSource.WINDOWS,
        result=result,
        source_ip=raw.get("IpAddress", raw.get("source_ip", "0.0.0.0")),
        geo_country=raw.get("geo_country", "unknown"),
        geo_city=raw.get("geo_city", "unknown"),
        geo_lat=float(raw.get("geo_lat", 0.0)),
        geo_lon=float(raw.get("geo_lon", 0.0)),
        device_id=raw.get("WorkstationName", raw.get("device_id", "unknown")),
        device_type=raw.get("device_type", "workstation"),
        user_agent=raw.get("ProcessName", ""),
        session_id=raw.get("TargetLogonId", raw.get("session_id", "")),
        mfa_used=bool(raw.get("mfa_used", False)),
        raw=raw,
    )


def parse_okta_event(raw: dict) -> AuthEvent:
    """Parse an Okta System Log event."""
    outcome = raw.get("outcome", None)
    if outcome is not None:
        result_str = outcome.get("result", "FAILURE") if isinstance(outcome, dict) else str(outcome)
        result = AuthResult.SUCCESS if result_str == "SUCCESS" else AuthResult.FAILURE
    else:
        result = _parse_result(raw)

    ts = _parse_timestamp(raw.get("published", raw.get("timestamp", "")))

    actor = raw.get("actor", {})
    client = raw.get("client", {})
    geo = client.get("geographicalContext", {})

    return AuthEvent(
        timestamp=ts,
        username=actor.get("alternateId", raw.get("username", "unknown")),
        source=LogSource.OKTA,
        result=result,
        source_ip=client.get("ipAddress", raw.get("source_ip", "0.0.0.0")),
        geo_country=geo.get("country", raw.get("geo_country", "unknown")),
        geo_city=geo.get("city", raw.get("geo_city", "unknown")),
        geo_lat=float(geo.get("geolocation", {}).get("lat", raw.get("geo_lat", 0.0))),
        geo_lon=float(geo.get("geolocation", {}).get("lon", raw.get("geo_lon", 0.0))),
        device_id=client.get("device", raw.get("device_id", "unknown")),
        device_type=client.get("device", raw.get("device_type", "unknown")),
        user_agent=client.get("userAgent", {}).get("rawUserAgent", raw.get("user_agent", "")),
        session_id=raw.get("authenticationContext", {}).get("externalSessionId", raw.get("session_id", "")),
        mfa_used="MFA" in str(raw.get("eventType", "")) or bool(raw.get("mfa_used", False)),
        raw=raw,
    )


def parse_aws_event(raw: dict) -> AuthEvent:
    """Parse an AWS CloudTrail ConsoleLogin / AssumeRole event."""
    response = raw.get("responseElements", None)
    if response is not None:
        result_str = response.get("ConsoleLogin", "Failure") if isinstance(response, dict) else "Failure"
        result = AuthResult.SUCCESS if result_str == "Success" else AuthResult.FAILURE
    else:
        result = _parse_result(raw)

    ts = _parse_timestamp(raw.get("eventTime", raw.get("timestamp", "")))

    user_identity = raw.get("userIdentity", {})
    additional = raw.get("additionalEventData", {})

    return AuthEvent(
        timestamp=ts,
        username=user_identity.get("userName", user_identity.get("arn", raw.get("username", "unknown"))),
        source=LogSource.AWS,
        result=result,
        source_ip=raw.get("sourceIPAddress", raw.get("source_ip", "0.0.0.0")),
        geo_country=raw.get("geo_country", "unknown"),
        geo_city=raw.get("geo_city", "unknown"),
        geo_lat=float(raw.get("geo_lat", 0.0)),
        geo_lon=float(raw.get("geo_lon", 0.0)),
        device_id=raw.get("device_id", "unknown"),
        device_type=raw.get("device_type", "unknown"),
        user_agent=raw.get("userAgent", ""),
        session_id=raw.get("requestID", raw.get("session_id", "")),
        mfa_used=additional.get("MFAUsed", "") == "Yes" or bool(raw.get("mfa_used", False)),
        raw=raw,
    )


def parse_webapp_event(raw: dict) -> AuthEvent:
    """Parse a web application authentication event (login/logout/password_reset/etc.)."""
    event_type = raw.get("event_type", "").lower()
    result_str = raw.get("result", "").lower()

    # Map event_type + result to AuthResult
    if event_type == "account_lockout":
        result = AuthResult.LOCKED_OUT
    elif event_type == "mfa_challenge" or result_str == "mfa_challenge":
        result = AuthResult.MFA_CHALLENGE
    elif result_str in ("success", "failure", "locked_out"):
        result = AuthResult(result_str)
    else:
        # Fallback: derive from status_code
        status_code = raw.get("status_code", 0)
        if status_code in (401, 403):
            result = AuthResult.FAILURE
        elif status_code == 423:
            result = AuthResult.LOCKED_OUT
        elif status_code == 200:
            result = AuthResult.SUCCESS
        else:
            result = _parse_result(raw)

    ts = _parse_timestamp(raw.get("timestamp", ""))

    return AuthEvent(
        timestamp=ts,
        username=raw.get("username", "unknown"),
        source=LogSource.WEBAPP,
        result=result,
        source_ip=raw.get("source_ip", "0.0.0.0"),
        geo_country=raw.get("geo_country", "unknown"),
        geo_city=raw.get("geo_city", "unknown"),
        geo_lat=float(raw.get("geo_lat", 0.0)),
        geo_lon=float(raw.get("geo_lon", 0.0)),
        device_id=raw.get("device_id", "unknown"),
        device_type="browser",
        user_agent=raw.get("user_agent", ""),
        session_id=raw.get("session_id", ""),
        mfa_used=bool(raw.get("mfa_used", False)),
        raw=raw,
    )


def parse_linux_event(raw: dict) -> AuthEvent:
    """Parse a Linux authentication event (SSH, sudo, su, PAM)."""
    auth_service = raw.get("auth_service", "").lower()
    result_str = raw.get("result", "").lower()

    if auth_service == "ssh":
        # SSH: "Accepted" → SUCCESS, "Failed" → FAILURE
        msg = raw.get("message", "")
        if "Accepted" in msg:
            result = AuthResult.SUCCESS
        elif "Failed" in msg:
            result = AuthResult.FAILURE
        elif result_str in ("success", "failure"):
            result = AuthResult(result_str)
        else:
            result = _parse_result(raw)
    elif auth_service == "sudo":
        # Sudo: check for explicit success/failure
        msg = raw.get("message", "")
        if "NOT" in msg or result_str == "failure":
            result = AuthResult.FAILURE
        elif result_str == "success":
            result = AuthResult.SUCCESS
        else:
            result = _parse_result(raw)
    elif auth_service == "su":
        # Su: "Successful su" → SUCCESS, "FAILED su" → FAILURE
        msg = raw.get("message", "")
        if "Successful su" in msg or result_str == "success":
            result = AuthResult.SUCCESS
        elif "FAILED su" in msg or result_str == "failure":
            result = AuthResult.FAILURE
        else:
            result = _parse_result(raw)
    elif auth_service == "pam":
        # PAM: "session opened" → SUCCESS, "authentication failure" → FAILURE
        msg = raw.get("message", "")
        if "session opened" in msg or result_str == "success":
            result = AuthResult.SUCCESS
        elif "authentication failure" in msg or result_str == "failure":
            result = AuthResult.FAILURE
        elif result_str == "locked_out":
            result = AuthResult.LOCKED_OUT
        else:
            result = _parse_result(raw)
    else:
        result = _parse_result(raw)

    ts = _parse_timestamp(raw.get("timestamp", ""))

    return AuthEvent(
        timestamp=ts,
        username=raw.get("username", "unknown"),
        source=LogSource.LINUX,
        result=result,
        source_ip=raw.get("source_ip", "0.0.0.0"),
        geo_country=raw.get("geo_country", "unknown"),
        geo_city=raw.get("geo_city", "unknown"),
        geo_lat=float(raw.get("geo_lat", 0.0)),
        geo_lon=float(raw.get("geo_lon", 0.0)),
        device_id=raw.get("hostname", raw.get("device_id", "unknown")),
        device_type="server",
        user_agent=raw.get("user_agent", ""),
        session_id=raw.get("session_id", ""),
        mfa_used=bool(raw.get("mfa_used", False)),
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Unified loader
# ---------------------------------------------------------------------------

PARSERS = {
    LogSource.WINDOWS: parse_windows_event,
    LogSource.OKTA: parse_okta_event,
    LogSource.AWS: parse_aws_event,
    LogSource.WEBAPP: parse_webapp_event,
    LogSource.LINUX: parse_linux_event,
}


def load_events(path: Path, source: LogSource) -> list[AuthEvent]:
    """Load auth events from a JSON/JSONL file."""
    parser = PARSERS[source]
    events: list[AuthEvent] = []

    text = path.read_text()
    try:
        data = json.loads(text)
        if isinstance(data, list):
            records = data
        else:
            records = [data]
    except json.JSONDecodeError:
        # Try JSONL
        records = []
        for line in text.strip().splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))

    for rec in records:
        events.append(parser(rec))

    return events


def _parse_timestamp(ts_str: str) -> datetime:
    """Best-effort timestamp parsing."""
    if not ts_str:
        return datetime.now()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return datetime.now()
