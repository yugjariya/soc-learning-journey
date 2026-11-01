# Case study: suspicious SSH authentication

**Classification:** synthetic SOC lab, not a real incident. All times below are UTC on 20 October 2026. The source is `data/auth.log`; its SHA-256 and per-finding evidence are recorded in `reports/sample/alerts.json`.

## Objective and method

Identify authentication patterns worth investigation, distinguish them from routine login mistakes, and document proportionate response recommendations. Parse OpenSSH messages, normalize timestamps and IP addresses, correlate inclusive rolling windows, and retain original line references. Defaults are five failures in five minutes, five accounts for a spray pattern, and three sources plus five failures for distributed activity.

## Timeline and assessment

| UTC | Observation | Interpretation |
| --- | --- | --- |
| 09:00–09:01:40 | Routine users, two engineer failures then a successful login | Below the failure threshold; no detection |
| 09:03–09:05:20 | Eight admin failures from `203.0.113.10` | Repeated password-guessing pattern; threshold first reached at 09:04:20 |
| 09:06:10 | Admin accepted public-key authentication from that address | Prioritize investigation, but a successful public key does not show that password guessing succeeded |
| 09:08:20–09:09:35 | Six different accounts fail from `198.51.100.23` | Consistent with an account sweep/spray; actual passwords are unavailable |
| 09:11:40–09:13:20 | Six service-account failures from three addresses | Distributed attempts; no proof the sources share an operator |
| 09:15 | Ordinary deploy success | No qualifying prior burst |

The engine produces **four findings: three high, one critical**. Repeated failures and suspicious success share eight failure records; they are related detections, not two separate confirmed incidents. There are 22 unique failure records in the complete fixture.

## Evidence and investigation decisions

1. Preserve the raw log with its hash and collection context. The report references physical lines, so verify against the unchanged input.
2. Confirm that `gateway-01` is the intended destination, clocks are synchronized, and ingestion has not duplicated records.
3. For admin, validate the public key and source against approved administration, then review session commands and endpoint telemetry. A legitimate key-based retry could explain the sequence.
4. For the account sweep and service-account attempts, check authorized assessments, VPN/NAT egress, and broken automation before attribution or containment.
5. If activity is confirmed unauthorized, follow incident policy to restrict access, revoke affected sessions, rotate affected credentials or keys, and check for further access.

## Outcome and gaps

The lab demonstrates detection and investigation preparation. It does not establish compromise, actor identity, or completed containment. No endpoint process telemetry, key fingerprint inventory, MFA records, or account-owner response is supplied. The Splunk searches are supplied for deployment and have not been run against a live Splunk instance.

The [response playbook](PLAYBOOK.md) describes what an analyst would collect next. Regenerate the results with the command in the project README.
