#!/usr/bin/env python3
"""
UEBA — User and Entity Behavior Analytics from Auth Logs

Usage:
  # Generate synthetic test data
  python main.py generate --output sample_data/

  # Run analysis on log files
  python main.py analyze --input sample_data/all_auth_logs.json --source auto

  # Run full pipeline: generate + analyze
  python main.py demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

from models import AuthEvent, LogSource, load_events, PARSERS
from features import extract_features, FEATURE_NAMES
from detector import UEBADetector
from generate_logs import generate_dataset, save_dataset


# ---------------------------------------------------------------------------
# Unified loader for "auto" source detection
# ---------------------------------------------------------------------------

def load_auto(path: Path) -> list[AuthEvent]:
    """Load events auto-detecting the source from each record's 'source' field."""
    text = path.read_text()
    try:
        data = json.loads(text)
        records = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        records = [json.loads(line) for line in text.strip().splitlines() if line.strip()]

    events = []
    for rec in records:
        src_str = rec.get("source", "").lower()
        if src_str in ("windows",):
            src = LogSource.WINDOWS
        elif src_str in ("okta",):
            src = LogSource.OKTA
        elif src_str in ("aws",):
            src = LogSource.AWS
        elif src_str in ("webapp",):
            src = LogSource.WEBAPP
        else:
            src = LogSource.OKTA  # fallback
        events.append(PARSERS[src](rec))
    return events


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def print_report(results, user_features_map, ground_truth=None):
    """Print ranked anomaly report to stdout."""

    anomalies = [r for r in results if r.is_anomaly]
    normals = [r for r in results if not r.is_anomaly]

    print("\n" + "=" * 80)
    print("  UEBA ANOMALY DETECTION REPORT")
    print("=" * 80)
    print(f"  Total users analyzed : {len(results)}")
    print(f"  Anomalies detected   : {len(anomalies)}")
    print(f"  Normal users         : {len(normals)}")
    print("=" * 80)

    # Anomaly details
    print("\n" + "-" * 80)
    print("  RANKED ANOMALIES (highest risk first)")
    print("-" * 80)

    for r in anomalies:
        print(f"\n  #{r.rank}  {r.username}")
        print(f"       Anomaly Score : {r.anomaly_score:.4f}")
        print(f"       Events        : {r.raw_features.get('avg_events_per_day', 0):.1f}/day")
        print(f"       Countries     : {int(r.raw_features.get('unique_countries', 0))}")
        print(f"       Failure Rate  : {r.raw_features.get('failure_ratio', 0):.1%}")
        print(f"       Off-Hours     : {r.raw_features.get('off_hours_ratio', 0):.1%}")
        print(f"       Device Churn  : {r.raw_features.get('device_churn_rate', 0):.2f}")
        print(f"       Max Geo Vel.  : {r.raw_features.get('geo_velocity_max_kmh', 0):,.0f} km/h")
        if r.top_reasons:
            print("       Reasons:")
            for reason in r.top_reasons:
                print(f"         - {reason}")

    # Feature distribution summary
    print("\n" + "-" * 80)
    print("  FEATURE DISTRIBUTION (all users)")
    print("-" * 80)
    print(f"  {'Feature':<28s} {'Mean':>10s} {'Std':>10s} {'Min':>10s} {'Max':>10s}")
    print(f"  {'─' * 28} {'─' * 10} {'─' * 10} {'─' * 10} {'─' * 10}")

    all_vecs = np.array([r.to_vector() for r in user_features_map])
    for i, name in enumerate(FEATURE_NAMES):
        col = all_vecs[:, i]
        print(f"  {name:<28s} {col.mean():>10.2f} {col.std():>10.2f} {col.min():>10.2f} {col.max():>10.2f}")

    # Ground truth comparison
    if ground_truth:
        known = set(ground_truth.get("anomalous_users", []))
        detected = set(r.username for r in anomalies)
        tp = detected & known
        fp = detected - known
        fn = known - detected

        print("\n" + "-" * 80)
        print("  GROUND TRUTH COMPARISON")
        print("-" * 80)
        print(f"  Known anomalous users  : {sorted(known)}")
        print(f"  Detected anomalies     : {sorted(detected)}")
        print(f"  True Positives         : {sorted(tp)} ({len(tp)})")
        print(f"  False Positives        : {sorted(fp)} ({len(fp)})")
        print(f"  False Negatives        : {sorted(fn)} ({len(fn)})")
        precision = len(tp) / max(len(detected), 1)
        recall = len(tp) / max(len(known), 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        print(f"  Precision              : {precision:.2%}")
        print(f"  Recall                 : {recall:.2%}")
        print(f"  F1 Score               : {f1:.2%}")

    print("\n" + "=" * 80)

    return anomalies


def save_results(results, output_path: Path):
    """Save full results as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = [r.to_dict() for r in results]
    output_path.write_text(json.dumps(data, indent=2))
    print(f"\nResults saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_generate(args):
    events, anomalous = generate_dataset(
        days=args.days,
        n_normal=args.normal_users,
        n_anomalous=args.anomalous_users,
        seed=args.seed,
    )
    save_dataset(Path(args.output), events, anomalous)


def cmd_analyze(args):
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    # Load events
    if args.source == "auto":
        events = load_auto(input_path)
    else:
        src = LogSource(args.source)
        events = load_events(input_path, src)
    print(f"Loaded {len(events)} auth events from {input_path}")

    # Extract features
    user_features = extract_features(events)
    print(f"Extracted features for {len(user_features)} users")

    # Run detection
    detector = UEBADetector(
        contamination=args.contamination,
        n_estimators=args.estimators,
    )
    results = detector.fit_predict(user_features)

    # Load ground truth if available
    gt_path = input_path.parent / "ground_truth.json"
    ground_truth = None
    if gt_path.exists():
        ground_truth = json.loads(gt_path.read_text())

    # Report
    print_report(results, user_features, ground_truth)

    # Save JSON results
    out = Path(args.output) if args.output else input_path.parent / "ueba_results.json"
    save_results(results, out)


def cmd_demo(args):
    """Full pipeline: generate synthetic data → analyze → report."""
    print("=" * 80)
    print("  UEBA DEMO — Generating synthetic auth logs + running anomaly detection")
    print("=" * 80)

    data_dir = Path("sample_data")
    events, anomalous = generate_dataset(
        days=30, n_normal=20, n_anomalous=5, seed=42,
    )
    save_dataset(data_dir, events, anomalous)

    # Parse all events through the normalized model
    all_events = load_auto(data_dir / "all_auth_logs.json")
    print(f"\nLoaded {len(all_events)} normalized auth events")

    user_features = extract_features(all_events)
    print(f"Extracted features for {len(user_features)} users")

    detector = UEBADetector(contamination=0.15, n_estimators=200)
    results = detector.fit_predict(user_features)

    ground_truth = json.loads((data_dir / "ground_truth.json").read_text())
    print_report(results, user_features, ground_truth)
    save_results(results, data_dir / "ueba_results.json")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="UEBA — User and Entity Behavior Analytics from Auth Logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # generate
    gen = sub.add_parser("generate", help="Generate synthetic auth logs")
    gen.add_argument("--output", default="sample_data/", help="Output directory")
    gen.add_argument("--days", type=int, default=30)
    gen.add_argument("--normal-users", type=int, default=20)
    gen.add_argument("--anomalous-users", type=int, default=5)
    gen.add_argument("--seed", type=int, default=42)

    # analyze
    ana = sub.add_parser("analyze", help="Analyze auth logs for anomalies")
    ana.add_argument("--input", required=True, help="Path to auth log JSON/JSONL")
    ana.add_argument("--source", default="auto", choices=["auto", "windows", "okta", "aws", "webapp"])
    ana.add_argument("--contamination", type=float, default=0.15,
                     help="Expected proportion of anomalies (0.01-0.5)")
    ana.add_argument("--estimators", type=int, default=200)
    ana.add_argument("--output", default=None, help="Output JSON path")

    # demo
    sub.add_parser("demo", help="Run full demo pipeline")

    args = parser.parse_args()
    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
