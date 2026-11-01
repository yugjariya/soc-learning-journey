# Synthetic SSH lab

## Scope and evidence

Source: `auth.log` · SHA-256: `d18e58fb08034400d3d13820d4fb2aa47a95414652db7a877f496e613d4c1793`

Analyzed 27 authentication events: 22 failures and 5 successes. Skipped 1 unrelated lines; 0 authentication lines could not be parsed.

Counts describe all parsed input, including allowlisted sources. Alert rules exclude allowlisted sources.

Event range (UTC): 2026-10-20T09:00:00+00:00 to 2026-10-20T09:15:00+00:00

## Findings

### BF-e968866203df: Repeated password failures

**Severity:** high · **Host:** `gateway-01` · **ATT&CK:** T1110.001

Repeated failed SSH logins for one account from one source.

- UTC interval: 2026-10-20T09:03:00+00:00 — 2026-10-20T09:05:20+00:00
- Source addresses: 203.0.113.10
- Accounts: admin
- Distinct failure records in evidence: 8
- Original log line numbers: 6, 7, 8, 9, 10, 11, 12, 13

### BF-f13ee1d60c3c: Success after failure burst

**Severity:** critical · **Host:** `gateway-01` · **ATT&CK:** T1078

Successful SSH login followed a qualifying failure burst; investigate possible account compromise.

- UTC interval: 2026-10-20T09:03:00+00:00 — 2026-10-20T09:06:10+00:00
- Source addresses: 203.0.113.10
- Accounts: admin
- Distinct failure records in evidence: 8
- Original log line numbers: 6, 7, 8, 9, 10, 11, 12, 13, 14

### BF-f68d218d5f91: Password-spray pattern

**Severity:** high · **Host:** `gateway-01` · **ATT&CK:** T1110.003

One source attempted SSH logins against multiple accounts.

- UTC interval: 2026-10-20T09:08:20+00:00 — 2026-10-20T09:09:35+00:00
- Source addresses: 198.51.100.23
- Accounts: alice, bob, charlie, dana, erin, frank
- Distinct failure records in evidence: 6
- Original log line numbers: 15, 16, 17, 18, 19, 20

### BF-ea0a824f474d: Distributed login attempts

**Severity:** high · **Host:** `gateway-01` · **ATT&CK:** T1110.001

Multiple sources attempted SSH logins against one account.

- UTC interval: 2026-10-20T09:11:40+00:00 — 2026-10-20T09:13:20+00:00
- Source addresses: 203.0.113.70, 203.0.113.71, 203.0.113.72
- Accounts: service
- Distinct failure records in evidence: 6
- Original log line numbers: 21, 22, 23, 24, 25, 26

## Assessment and response

These are behavioral detections. A successful login after failures requires investigation; it does not prove account compromise. Authentication logs do not reveal whether the same password was tried against multiple accounts. Multiple sources do not establish common ownership.

1. Preserve original logs and hash; confirm clock offsets, parser coverage, and asset ownership.
2. Compare accounts and source addresses with approved activity, NAT/VPN egress, and scheduled automation.
3. Review successful login method, session activity, process execution, and account-owner confirmation.
4. If unauthorized activity is confirmed, follow the response policy: restrict abusive sources, revoke affected sessions, and rotate affected credentials or keys.
5. Reduce exposure with MFA where supported, key-based SSH, access restrictions, rate limits, and monitoring. Validate changes before rollout.

No containment action was executed by this analyzer. See `docs/PLAYBOOK.md` for investigation steps.

## Detection configuration

```json
{
  "failure_threshold": 5,
  "window_seconds": 300,
  "spray_user_threshold": 5,
  "distributed_source_threshold": 3,
  "success_window_seconds": 600,
  "allowlist": []
}
```

Yearless syslog assumes the configured year and fixed UTC offset. Split files across year boundaries before analysis. Duplicate source records are counted separately; deduplicate upstream. Batch analysis holds parsed events in memory.
