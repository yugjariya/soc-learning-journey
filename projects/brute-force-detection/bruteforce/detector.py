"""Deterministic, inclusive sliding-window detections with evidence references."""

import hashlib
import ipaddress
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timezone
from typing import Dict, Iterable, List, Tuple

from .parser import Event


@dataclass(frozen=True)
class Config:
    failure_threshold: int = 5
    window_seconds: int = 300
    spray_user_threshold: int = 5
    distributed_source_threshold: int = 3
    success_window_seconds: int = 600
    allowlist: Tuple[str, ...] = ()

    def __post_init__(self):
        for name in ("failure_threshold", "window_seconds", "spray_user_threshold",
                     "distributed_source_threshold", "success_window_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(name + " must be a positive integer")
        if isinstance(self.allowlist, str):
            raise ValueError("allowlist must be a sequence of IP addresses or CIDRs")
        try:
            entries = tuple(self.allowlist)
            networks = tuple(ipaddress.ip_network(entry, strict=False) for entry in entries)
        except (TypeError, ValueError) as exc:
            raise ValueError("allowlist contains an invalid IP address or CIDR") from exc
        object.__setattr__(self, "allowlist", entries)
        # Keep derived objects outside dataclass fields so asdict(config) stays JSON serializable.
        object.__setattr__(self, "_networks", networks)


def _order(event: Event):
    return event.timestamp, event.line_number


def _iso(event: Event) -> str:
    return event.timestamp.astimezone(timezone.utc).isoformat()


def _episodes(events, window_seconds, qualifies):
    """Merge consecutive qualifying windows; retain the qualifying anchors.

    Evidence is a union of windows, so a long continuous episode can contain
    more failures and span more time than one configured detection window.
    """
    window = deque()
    active = None
    episodes = []
    for index, event in events:
        window.append((index, event))
        while (event.timestamp - window[0][1].timestamp).total_seconds() > window_seconds:
            window.popleft()
        if qualifies(window):
            if active is None:
                active = {"evidence": {}, "anchors": []}
                episodes.append(active)
            active["evidence"].update(window)
            active["anchors"].append((index, event))
        else:
            active = None
    return episodes


_DESCRIPTIONS = {
    "brute_force": "Repeated failed SSH logins for one account from one source.",
    "password_spray": "One source attempted SSH logins against multiple accounts.",
    "distributed_attack": "Multiple sources attempted SSH logins against one account.",
    "suspicious_success": "Successful SSH login followed a qualifying failure burst; investigate possible account compromise.",
}
_MITRE = {
    "brute_force": "T1110.001", "password_spray": "T1110.003",
    "distributed_attack": "T1110.001", "suspicious_success": "T1078",
}


def _alert(kind, evidence):
    events = sorted(evidence.values(), key=_order)
    alert = {
        "type": kind,
        "severity": "critical" if kind == "suspicious_success" else "high",
        "first_seen": _iso(events[0]),
        "last_seen": _iso(events[-1]),
        "host": events[0].host,
        "source_ips": sorted({event.source_ip for event in events}),
        "usernames": sorted({event.username for event in events}),
        "failure_count": sum(event.outcome == "failure" for event in events),
        "evidence_lines": sorted({event.line_number for event in events}),
        "description": _DESCRIPTIONS[kind],
        "mitre_technique": _MITRE[kind],
    }
    fingerprint = json.dumps(alert, sort_keys=True, separators=(",", ":"))
    alert["id"] = "BF-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12]
    return alert


def analyze(events: Iterable[Event], config: Config) -> List[dict]:
    """Detect attack patterns without network access or automatic containment.

    All correlations include the destination host. Same-time records are
    ordered by original line number: a success before the fifth failure does
    not count as a success after a five-failure burst.
    """
    retained = []
    for index, event in enumerate(events):
        if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
            raise ValueError("event timestamps must include a timezone")
        if event.outcome not in ("failure", "success"):
            raise ValueError("event outcome must be failure or success")
        address = ipaddress.ip_address(event.source_ip)
        if any(address in network for network in config._networks):
            continue
        retained.append((index, event))
    retained.sort(key=lambda item: _order(item[1]))
    failures = [item for item in retained if item[1].outcome == "failure"]
    alerts = []

    # The same failure can legitimately support more than one detection type.
    definitions = (
        ("brute_force", lambda event: (event.host, event.source_ip, event.username),
         lambda window: len(window) >= config.failure_threshold),
        ("password_spray", lambda event: (event.host, event.source_ip),
         lambda window: len({event.username for _, event in window}) >= config.spray_user_threshold),
        ("distributed_attack", lambda event: (event.host, event.username),
         lambda window: len(window) >= config.failure_threshold and
         len({event.source_ip for _, event in window}) >= config.distributed_source_threshold),
    )
    brute_episodes = {}
    for kind, group_key, qualifies in definitions:
        groups = defaultdict(list)
        for item in failures:
            groups[group_key(item[1])].append(item)
        for key, items in groups.items():
            episodes = _episodes(items, config.window_seconds, qualifies)
            alerts.extend(_alert(kind, episode["evidence"]) for episode in episodes)
            if kind == "brute_force":
                brute_episodes[key] = episodes

    # Use an already reached threshold, never a total of sparse historic failures.
    success_evidence: Dict[tuple, dict] = {}
    for index, success in retained:
        if success.outcome != "success":
            continue
        key = (success.host, success.source_ip, success.username)
        episodes = brute_episodes.get(key, [])
        for episode_number in range(len(episodes) - 1, -1, -1):
            episode = episodes[episode_number]
            prior_anchors = [event for _, event in episode["anchors"] if _order(event) < _order(success)]
            if not prior_anchors:
                continue
            anchor = prior_anchors[-1]
            if (success.timestamp - anchor.timestamp).total_seconds() > config.success_window_seconds:
                break
            bucket = success_evidence.setdefault((key, episode_number), {})
            bucket.update({identity: event for identity, event in episode["evidence"].items()
                           if _order(event) <= _order(anchor)})
            bucket[index] = success
            break
    alerts.extend(_alert("suspicious_success", evidence) for evidence in success_evidence.values())
    return sorted(alerts, key=lambda alert: (alert["first_seen"], alert["type"], alert["id"]))
