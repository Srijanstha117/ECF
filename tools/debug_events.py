"""
debug_events.py

Troubleshooting: prints every raw Docker event, unfiltered. listener.py
only reacts to events with Type "container" and Action "kill" / "die",
reading Actor.ID and timeNano; if the Docker Engine ever sends a
different shape, the listener would silently ignore everything, which
looks exactly like "nothing detected". This shows what is really sent.

Run it alongside (or instead of) the listener, then run and kill a test
container in another window.
"""

import docker

client = docker.from_env()

print("[*] Watching ALL raw events, no filtering... (Ctrl+C to stop)")
for event in client.events(decode=True):
    print(event)
