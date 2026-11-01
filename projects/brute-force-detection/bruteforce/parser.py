"""Parse OpenSSH password failures and password/public-key successes.

Traditional syslog timestamps have no year or timezone: callers must supply
the correct assumptions. This parser does not infer New Year rollover.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    source_ip: str
    username: str
    outcome: str
    line_number: int
    raw: str


@dataclass
class ParseResult:
    events: List[Event] = field(default_factory=list)
    skipped_lines: int = 0
    malformed_lines: int = 0


_HEADER = re.compile(
    r"^(?P<timestamp>(?:[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|\S+)"
    r"\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s*(?P<message>.*)$"
)
_AUTH = re.compile(
    r"^(?P<action>Failed password|Accepted password|Accepted publickey) "
    r"for (?:invalid user )?(?P<username>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\d+) ssh2(?:\b.*)?$"
)
_AUTH_MARKER = re.compile(r"\b(?:Failed password|Accepted password|Accepted publickey)\b")
_SSH_MARKER = re.compile(r"\bsshd(?:-session)?(?:\[[^\]]*\])?:")
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}


def _timezone(offset: str) -> timezone:
    if not isinstance(offset, str) or not re.fullmatch(r"[+-]\d{2}:\d{2}", offset):
        raise ValueError("tz_offset must use +HH:MM or -HH:MM")
    hours, minutes = int(offset[1:3]), int(offset[4:6])
    if hours > 23 or minutes > 59:
        raise ValueError("tz_offset must be less than 24 hours with minutes below 60")
    sign = 1 if offset[0] == "+" else -1
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def _timestamp(value: str, year: int, assumed_tz: timezone) -> datetime:
    if re.match(r"^[A-Za-z]{3}\s", value):
        month, day, clock = value.split()
        hour, minute, second = (int(part) for part in clock.split(":"))
        stamp = datetime(year, _MONTHS[month], int(day), hour, minute, second, tzinfo=assumed_tz)
    else:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=assumed_tz)
    return stamp.astimezone(timezone.utc)


def parse_lines(lines: Iterable[str], year: int = 2026, tz_offset: str = "+00:00") -> ParseResult:
    """Return parsed events plus separate unrelated/malformed line counters.

    A malformed line is a recognizable SSH authentication record whose header,
    date, source address, port or message cannot be parsed. Other lines are
    skipped. Original physical line numbers are retained for investigation.
    """
    if isinstance(year, bool) or not isinstance(year, int) or not 1 <= year <= 9999:
        raise ValueError("year must be an integer between 1 and 9999")
    assumed_tz = _timezone(tz_offset)
    result = ParseResult()
    for line_number, line in enumerate(lines, 1):
        raw = line.rstrip("\r\n")
        if not _SSH_MARKER.search(raw) or not _AUTH_MARKER.search(raw):
            result.skipped_lines += 1
            continue
        header = _HEADER.fullmatch(raw)
        auth = _AUTH.fullmatch(header["message"]) if header else None
        if not header or not auth:
            result.malformed_lines += 1
            continue
        try:
            stamp = _timestamp(header["timestamp"], year, assumed_tz)
            source = str(ipaddress.ip_address(auth["ip"]))
            if not 0 < int(auth["port"]) <= 65535:
                raise ValueError("invalid source port")
        except (ValueError, KeyError, OverflowError):
            result.malformed_lines += 1
            continue
        result.events.append(Event(
            timestamp=stamp, host=header["host"], source_ip=source,
            username=auth["username"],
            outcome="failure" if auth["action"] == "Failed password" else "success",
            line_number=line_number, raw=raw,
        ))
    return result
