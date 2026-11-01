"""Command-line entry point: python -m bruteforce."""
import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .detector import Config, analyze
from .parser import parse_lines
from .report import write_reports


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze OpenSSH authentication logs and write investigation reports.")
    parser.add_argument("--input", type=Path, required=True, help="UTF-8 OpenSSH syslog file")
    parser.add_argument("--output", type=Path, default=Path("reports/local"), help="Report directory (default: reports/local)")
    parser.add_argument("--label", default="Authentication log analysis", help="Report title; identify synthetic data explicitly")
    parser.add_argument("--year", type=int, default=datetime.now(timezone.utc).year, help="Assumed year for traditional syslog")
    parser.add_argument("--timezone", default="+00:00", help="Assumed fixed UTC offset for traditional syslog, e.g. +05:30")
    parser.add_argument("--threshold", type=int, default=5, help="Failures needed in a rolling window")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--spray-users", type=int, default=5)
    parser.add_argument("--distributed-sources", type=int, default=3)
    parser.add_argument("--success-window-seconds", type=int, default=600)
    parser.add_argument("--allow", action="append", default=[], metavar="IP_OR_CIDR", help="Exclude a trusted source; repeat as needed")
    parser.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if detections are present; input errors exit 2")
    args = parser.parse_args(argv)
    try:
        config = Config(failure_threshold=args.threshold, window_seconds=args.window_seconds,
                        spray_user_threshold=args.spray_users,
                        distributed_source_threshold=args.distributed_sources,
                        success_window_seconds=args.success_window_seconds, allowlist=tuple(args.allow))
        targets = {args.output.resolve() / name for name in
                   ("alerts.json", "events.jsonl", "investigation.md", "dashboard.html")}
        if args.input.resolve() in targets:
            raise ValueError("Input file must not be one of the output files")
        raw = args.input.read_bytes()
        parsed = parse_lines(raw.decode("utf-8").splitlines(), year=args.year, tz_offset=args.timezone)
        alerts = analyze(parsed.events, config)
        events = sorted(parsed.events, key=lambda event: (event.timestamp, event.line_number))
        report = {
            "schema_version": "1.0", "label": args.label,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": {"name": args.input.name, "sha256": hashlib.sha256(raw).hexdigest(),
                       "assumed_year": args.year, "assumed_timezone": args.timezone},
            "config": asdict(config),
            "summary": {"total_lines": len(raw.decode("utf-8").splitlines()),
                        "parsed_events": len(events), "failures": sum(e.outcome == "failure" for e in events),
                        "successes": sum(e.outcome == "success" for e in events),
                        "skipped_lines": parsed.skipped_lines, "malformed_lines": parsed.malformed_lines,
                        "unique_sources": len({e.source_ip for e in events}), "alerts": len(alerts),
                        "first_event": events[0].timestamp.isoformat() if events else None,
                        "last_event": events[-1].timestamp.isoformat() if events else None},
            "alerts": alerts,
        }
        write_reports(report, events, args.output)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    print(f"Parsed {len(events)} authentication events; {len(alerts)} alerts.")
    print(f"Skipped {parsed.skipped_lines} unrelated lines; {parsed.malformed_lines} malformed authentication lines.")
    print(f"Reports: {args.output.resolve()}")
    return 1 if args.fail_on_alert and alerts else 0


if __name__ == "__main__":
    sys.exit(main())
