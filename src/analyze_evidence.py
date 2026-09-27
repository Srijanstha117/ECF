"""
analyze_evidence.py

Summarizes every evidence file captured so far into one readable table,
sorted by how long the container actually lived (container_lifetime_seconds).
Makes it easy to see exactly where the rescue threshold sits, without
opening files one by one or uploading them individually.

Run with:   python analyze_evidence.py
"""

import glob
import json
import os

EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "evidence")


def summarize(path):
    with open(path) as f:
        data = json.load(f)

    net = data.get("network_state", {})
    proc = data.get("process_list", {})

    return {
        "name": data.get("container_name", "?"),
        "lifetime_s": data.get("container_lifetime_seconds"),
        "network_source": net.get("source", "?"),
        "network_age_s": net.get("snapshot_age_seconds"),
        "process_source": proc.get("source", "?"),
    }


def main():
    files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "*.json")))
    if not files:
        print("No evidence files found yet.")
        return

    rows = [summarize(f) for f in files]
    rows.sort(key=lambda r: (r["lifetime_s"] is None, r["lifetime_s"]))

    print(f"{'Lifetime(s)':<13}{'Network source':<45}{'Age(s)':<9}{'Container':<20}")
    print("-" * 90)
    for r in rows:
        lifetime_str = f"{r['lifetime_s']:.3f}" if r["lifetime_s"] is not None else "unknown"
        age_str = f"{r['network_age_s']:.3f}" if r["network_age_s"] is not None else "-"
        print(f"{lifetime_str:<13}{r['network_source']:<45}{age_str:<9}{r['name']:<20}")


if __name__ == "__main__":
    main()
