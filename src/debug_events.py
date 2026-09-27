"""
debug_events.py

Temporary diagnostic tool -- prints every raw Docker event with no
filtering, so we can see exactly what fields your Docker/docker-py
version actually sends. listener.py assumes an event dict with
"Type" == "container" and "status" == "die", but event formats have
shifted across Docker Engine API versions, and if that assumption is
wrong, listener.py silently filters everything out and never prints
anything -- which looks exactly like "nothing detected."

Run this INSTEAD of listener.py, then in another window run + kill a
test container, and copy back everything this prints.
"""

import docker

client = docker.from_env()

print("[*] Watching ALL raw events, no filtering... (Ctrl+C to stop)")
for event in client.events(decode=True):
    print(event)
