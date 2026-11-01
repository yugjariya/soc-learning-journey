#!/usr/bin/env python3
"""Create a deterministic synthetic SSH log. Makes no network connections."""
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate():
    base = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    rows = []

    def event(seconds, user, ip, outcome="failure", host="gateway-01"):
        stamp = (base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
        message = ("Failed password for invalid user" if outcome == "failure"
                   else "Accepted publickey for")
        rows.append((seconds, f"{stamp} {host} sshd[4100]: {message} {user} from {ip} port 50222 ssh2"))

    # Ordinary logins and two typing mistakes: should not alert.
    for second, user in [(0, "analyst"), (45, "engineer"), (900, "deploy")]:
        event(second, user, "192.0.2.10", "success")
    for second in [60, 85]:
        event(second, "engineer", "192.0.2.10")
    event(100, "engineer", "192.0.2.10", "success")
    # Eight failures, followed by success for the same source/account/host.
    for i in range(8):
        event(180 + i * 20, "admin", "203.0.113.10")
    event(370, "admin", "203.0.113.10", "success")
    # Six accounts from one source: spraying-like behavior, not proof of passwords reused.
    for i, user in enumerate(["alice", "bob", "charlie", "dana", "erin", "frank"]):
        event(500 + i * 15, user, "198.51.100.23")
    # Six failures against one account across three source addresses.
    for i in range(6):
        event(700 + i * 20, "service", f"203.0.113.{70 + i % 3}")
    # One unrelated service message exercises skipped-line accounting.
    rows.append((950, "2026-10-20T09:15:50Z gateway-01 systemd[1]: Started Daily Cleanup."))
    return "\n".join(row for _, row in sorted(rows, key=lambda item: item[0])) + "\n"


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "data" / "auth.log"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(generate(), encoding="utf-8")
    print(f"Wrote {target}")
