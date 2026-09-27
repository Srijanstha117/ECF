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
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Skipping unreadable file {os.path.basename(path)}: {e}")
        return None

    net = data.get("network_state", {})
    proc = data.get("process_list", {})

    return {
        "name": data.get("container_name", "?"),
        "lifetime_s": data.get("container_lifetime_seconds"),
        "network_source": net.get("source", "?"),
        "network_age_s": net.get("snapshot_age_seconds"),
        "process_source": proc.get("source", "?"),
        # Files without a "timing" block predate the timing fix: their
        # lifetime and age were measured from when the die handler ran,
        # ~0.3s after the real exit (Docker Desktop's die event is late).
        "legacy_timing": "timing" not in data,
    }


def main():
    files = sorted(glob.glob(os.path.join(EVIDENCE_DIR, "*.json")))
    if not files:
        print("No evidence files found yet.")
        return

    rows = [r for r in (summarize(f) for f in files) if r is not None]
    # Legacy rows are listed separately rather than interleaved: their
    # lifetimes are inflated, so sorting them among corrected rows would
    # misplace every one of them on the threshold.
    rows.sort(key=lambda r: (r["legacy_timing"], r["lifetime_s"] is None, r["lifetime_s"]))

    print(f"{'Lifetime(s)':<13}{'Network source':<22}{'Age(s)':<9}{'Timing':<8}{'Container':<20}")
    print("-" * 72)
    for r in rows:
        lifetime_str = f"{r['lifetime_s']:.3f}" if r["lifetime_s"] is not None else "unknown"
        age_str = f"{r['network_age_s']:.3f}" if r["network_age_s"] is not None else "-"
        timing_str = "legacy" if r["legacy_timing"] else "event"
        source_str = "LOST (both failed)" if r["network_source"].startswith("none") else r["network_source"]
        print(f"{lifetime_str:<13}{source_str:<22}{age_str:<9}{timing_str:<8}{r['name']:<20}")

    if any(r["legacy_timing"] for r in rows):
        print(
            "\nlegacy = captured before the timing fix. Its lifetime and age were\n"
            "measured when the die handler ran, not at the actual exit. Docker\n"
            "Desktop's die event fires ~0.3s after the exit, so both are overstated\n"
            "by about that much. Don't read legacy and event rows as one series."
        )


if __name__ == "__main__":
    main()
