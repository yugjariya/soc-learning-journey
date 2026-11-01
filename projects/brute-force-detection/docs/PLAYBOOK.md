# Authentication investigation playbook

This is a lab response procedure, not a record of actions taken on a real system. The analyzer reports patterns and never blocks addresses, disables accounts, or changes SSH settings.

## 1. Validate the finding

- Preserve the original log and its SHA-256. Retain the alert ID, source host, UTC interval, rule settings, and evidence line numbers.
- Check parsed, skipped, and malformed counts. Verify timezone/year assumptions, clock synchronization, ingestion delay, duplicate records, and rotated-log coverage.
- Confirm the destination is the affected SSH host rather than a collector. Identify account and system owners and business criticality.
- Compare source addresses with VPN/NAT egress, approved testing, administrators, deployment jobs, stale saved credentials, and service retries. Several accounts behind one address can be legitimate.

## 2. Scope activity

Review failures before and after the detected interval, including other destination hosts and accounts. Multiple sources targeting one account suggest distributed activity, but do not establish that the sources share an operator.

Prioritize a success after a qualifying burst. Check the authentication method, key fingerprint where available, account-owner confirmation, source history, session start/end, commands/processes, privilege changes, authorized-key modifications, and subsequent network access. Preserve endpoint and session evidence before remediation when operationally feasible.

For this fixture, the success uses **publickey**. Do not conclude that a password was guessed or that the login was unauthorized from this correlation alone.

## 3. Decide and contain

| Finding | Recommended decision |
| --- | --- |
| Approved activity or stale automation credentials | Record evidence; repair the job and narrowly tune the rule. |
| Unexplained failures without successful access | Escalate for review; consider scoped source restrictions and rate limits under local policy. |
| Confirmed unauthorized access | Activate incident response, preserve evidence, revoke affected sessions, restrict affected access, and rotate compromised credentials or keys. |
| Evidence missing or contradictory | Keep the case open and collect additional telemetry; do not label it a confirmed compromise. |

Assess shared-address and service-account impact before restricting a source or disabling an account. Record the owner, approved scope, expiry and rollback for changes. Broad lockouts can interrupt legitimate access.

## 4. Recover and improve

Validate known-good access and monitoring after remediation. Review SSH exposure, key management, MFA where supported, access restrictions, and rate limiting. Select controls based on the environment and test them before rollout. MITRE documents authentication protections and credential-management mitigations for [Brute Force](https://attack.mitre.org/techniques/T1110/).

Close the case with: disposition, timeline, affected assets/accounts, evidence references, actions actually taken, remaining uncertainty, and detection changes. A lack of alerts does not demonstrate safety: low-and-slow attacks, alternate authentication services, missing logs, and excluded sources can evade these rules.
