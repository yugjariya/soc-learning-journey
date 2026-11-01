import json
import unittest
from datetime import datetime, timedelta, timezone

from bruteforce import Config, Event, analyze, parse_lines


BASE = datetime(2026, 11, 1, tzinfo=timezone.utc)


def event(second=0, line=1, ip="192.0.2.10", user="admin", host="lab", outcome="failure"):
    return Event(BASE + timedelta(seconds=second), host, ip, user, outcome, line, "synthetic")


def alerts_of(events, kind, **kwargs):
    return [alert for alert in analyze(events, Config(**kwargs)) if alert["type"] == kind]


class ParserTests(unittest.TestCase):
    def test_openssh_formats_and_utc_normalization(self):
        parsed = parse_lines([
            "Nov  1 05:30:00 lab sshd[12]: Failed password for invalid user guest from 192.0.2.10 port 40000 ssh2\n",
            "2026-11-01T05:31:00+05:30 lab sshd[12]: Accepted publickey for admin from 2001:0db8::1 port 40000 ssh2: ED25519 SHA256:example",
            "2026-11-01T00:32:00Z lab sshd-session[12]: Accepted password for admin from 192.0.2.11 port 40000 ssh2",
        ], year=2026, tz_offset="+05:30")
        self.assertEqual(len(parsed.events), 3)
        self.assertEqual(parsed.events[0].timestamp, BASE)
        self.assertEqual(parsed.events[0].username, "guest")
        self.assertEqual(parsed.events[1].source_ip, "2001:db8::1")
        self.assertEqual(parsed.events[1].timestamp, BASE + timedelta(minutes=1))
        self.assertEqual(parsed.events[2].outcome, "success")
        self.assertEqual(parsed.events[2].line_number, 3)

    def test_malformed_and_unrelated_records_are_separate(self):
        parsed = parse_lines([
            "Nov 1 00:00:00 lab cron[1]: maintenance",
            "Nov 1 00:00:00 lab sshd[1]: Invalid user guest from 192.0.2.1 port 5",
            "Feb 30 00:00:00 lab sshd[1]: Failed password for admin from 192.0.2.1 port 5 ssh2",
            "Nov 1 00:00:00 lab sshd[1]: Failed password for admin from not-an-ip port 5 ssh2",
            "Nov 1 00:00:00 lab sshd[1]: Failed password for admin from 192.0.2.1 port 99999 ssh2",
            "Nov 1 00:00:00 lab sshd[1]: Failed password for admin",
            "not-a-date lab sshd[1]: Accepted password for admin from 192.0.2.1 port 5 ssh2",
        ])
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.skipped_lines, 2)
        self.assertEqual(parsed.malformed_lines, 5)

    def test_parser_option_validation(self):
        for year in (0, 10000, True):
            with self.assertRaises(ValueError):
                parse_lines([], year=year)
        for offset in ("UTC", "+24:00", "+01:60"):
            with self.assertRaises(ValueError):
                parse_lines([], tz_offset=offset)


class DetectorTests(unittest.TestCase):
    def test_threshold_and_inclusive_window_boundary(self):
        events = [event(second, line) for line, second in enumerate((0, 75, 150, 225, 300), 1)]
        self.assertEqual(len(alerts_of(events, "brute_force")), 1)
        self.assertEqual(alerts_of(events[:-1] + [event(301, 5)], "brute_force"), [])
        self.assertEqual(alerts_of(events[:-1], "brute_force"), [])

    def test_unsorted_input_is_deterministic_and_serializable(self):
        events = [event(second, second + 1) for second in range(8)]
        self.assertEqual(analyze(events, Config()), analyze(list(reversed(events)), Config()))
        json.dumps(analyze(events, Config()))

    def test_overlapping_windows_union_evidence_without_duplicates(self):
        events = [event(second, second + 1) for second in range(8)]
        alerts = alerts_of(events, "brute_force")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 8)
        self.assertEqual(alerts[0]["evidence_lines"], list(range(1, 9)))

    def test_separate_bursts_remain_separate(self):
        events = [event(second, index + 1) for index, second in enumerate((0, 1, 2, 3, 4, 1000, 1001, 1002, 1003, 1004))]
        self.assertEqual(len(alerts_of(events, "brute_force")), 2)

    def test_spray_requires_unique_accounts(self):
        events = [event(i, i + 1, user="user" + str(i)) for i in range(5)]
        alerts = alerts_of(events, "password_spray")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts_of([event(i, i + 1) for i in range(10)], "password_spray"), [])

    def test_distributed_requires_sources_and_failure_count(self):
        events = [event(i, i + 1, ip="192.0.2." + str(i % 3 + 1)) for i in range(5)]
        self.assertEqual(len(alerts_of(events, "distributed_attack")), 1)
        self.assertEqual(alerts_of(events[:3], "distributed_attack"), [])

    def test_no_cross_host_correlations(self):
        events = [event(i, i + 1, host="a" if i < 3 else "b") for i in range(5)]
        self.assertEqual(analyze(events, Config()), [])
        events = [event(i, i + 1, user="u" + str(i), host="a" if i < 3 else "b") for i in range(5)]
        self.assertEqual(alerts_of(events, "password_spray"), [])

    def test_allowlist_ipv4_and_ipv6(self):
        events = [event(i, i + 1) for i in range(5)]
        events += [event(i, i + 6, ip="2001:db8::5") for i in range(5)]
        self.assertEqual(analyze(events, Config(allowlist=("192.0.2.0/24", "2001:db8::/32"))), [])
        self.assertEqual(len(alerts_of(events, "brute_force", allowlist=("192.0.2.10",))), 1)

    def test_success_boundary_requires_prior_qualifying_burst(self):
        failures = [event(i, i + 1) for i in range(5)]
        alerts = alerts_of(failures + [event(604, 6, outcome="success")], "suspicious_success")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts[0]["evidence_lines"], [1, 2, 3, 4, 5, 6])
        self.assertEqual(alerts_of(failures + [event(605, 6, outcome="success")], "suspicious_success"), [])

    def test_sparse_failures_do_not_trigger_success_alert(self):
        failures = [event(i * 200, i + 1) for i in range(5)]
        self.assertEqual(alerts_of(failures + [event(801, 6, outcome="success")], "suspicious_success"), [])

    def test_success_must_match_host_source_and_user(self):
        failures = [event(i, i + 1) for i in range(5)]
        for changes in ({"host": "other"}, {"ip": "192.0.2.20"}, {"user": "other"}):
            self.assertEqual(alerts_of(failures + [event(5, 6, outcome="success", **changes)], "suspicious_success"), [])

    def test_same_timestamp_respects_line_order(self):
        failures = [event(0, i + 1) for i in range(5)]
        self.assertEqual(alerts_of(failures + [event(0, 0, outcome="success")], "suspicious_success"), [])
        self.assertEqual(len(alerts_of(failures + [event(0, 6, outcome="success")], "suspicious_success")), 1)

    def test_future_failures_do_not_inflate_success_evidence(self):
        events = [event(i, i + 1) for i in range(5)]
        events += [event(5, 6, outcome="success"), event(6, 7), event(7, 8)]
        alert = alerts_of(events, "suspicious_success")[0]
        self.assertEqual(alert["failure_count"], 5)
        self.assertEqual(alert["evidence_lines"], list(range(1, 7)))

    def test_invalid_configuration_is_rejected(self):
        for name in ("failure_threshold", "window_seconds", "spray_user_threshold",
                     "distributed_source_threshold", "success_window_seconds"):
            for value in (0, -1, 1.5, True):
                with self.assertRaises(ValueError):
                    Config(**{name: value})
        with self.assertRaises(ValueError):
            Config(allowlist=("invalid-address",))

    def test_empty_and_benign_successes_produce_no_alerts(self):
        self.assertEqual(analyze([], Config()), [])
        self.assertEqual(analyze([event(i, i + 1, outcome="success") for i in range(10)], Config()), [])


if __name__ == "__main__":
    unittest.main()
