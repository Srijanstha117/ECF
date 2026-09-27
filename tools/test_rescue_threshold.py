"""
test_rescue_threshold.py

Automates the "how much lead time does the poller actually need"
sweep, instead of manually juggling three terminals and hand-timing
docker commands for every data point.

Run this WHILE listener.py is already running in another window. This
script just starts a uniquely-named container, waits a given delay,
then kills it -- listener.py does the real capturing, exactly as if
you'd done it by hand. Check the evidence/ folder afterward for the
result matching this run's container name.

Usage:
    python test_rescue_threshold.py --delay 0.2
    python test_rescue_threshold.py --delay 1
    python test_rescue_threshold.py --delay 3

Suggested sweep to actually run, one at a time, checking evidence/
after each: 0.1, 0.3, 0.6, 1, 2, 4 seconds. That'll show roughly where
the rescue starts succeeding consistently rather than just confirming
it works at one comfortable delay.
"""

import argparse
import time
import uuid

import docker


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--delay",
        type=float,
        required=True,
        help="Seconds to wait after starting the container before killing it",
    )
    args = parser.parse_args()

    client = docker.from_env()
    name = f"rescuetest_{uuid.uuid4().hex[:8]}"

    print(f"[*] Starting container '{name}'...")
    client.containers.run(
        "alpine",
        'sh -c "echo hello > /tmp/test.txt; sleep 30"',
        name=name,
        detach=True,
    )

    print(f"[*] Waiting {args.delay}s before killing it...")
    time.sleep(args.delay)

    print(f"[*] Killing '{name}' now.")
    client.containers.get(name).kill()

    print(f"[*] Done. Check evidence/ for a file starting with '{name}_'")
    print(f"    (delay used: {args.delay}s)")


if __name__ == "__main__":
    main()
