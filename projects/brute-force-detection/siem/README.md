# Splunk monitoring lab

These SPL1 queries are **unexecuted templates** reviewed against official documentation. No Splunk instance was connected during project creation. The Python analyzer and its sample reports are independently runnable; this folder supplies the SIEM extension.

## Load the sample

1. In an authorized Splunk lab, create the `ssh_lab` index.
2. Use **Add Data → Upload** to ingest `data/auth.log` once. Select/create source type `bf:ssh` and index `ssh_lab`.
3. Configure one event per line and UTC timestamps using the supplied `props.conf` settings, or equivalent source-type settings in the upload preview. Check that the first event is `2026-10-20T09:00:00Z`, not upload time. Install parsing settings on the component performing parsing before ingestion; ask the Splunk administrator for managed deployments.
4. Search with **All time** for this fixed-date fixture. Confirm `index=ssh_lab sourcetype="bf:ssh" | stats count` returns **28** records, including one unrelated systemd message.
5. Run each `.spl` file in Search & Reporting. The regex extracts `dest` from the message's hostname; the indexed `host` may identify the collector instead.

The timestamp settings are specific to the included ISO UTC fixture. Traditional syslog requires different parsing assumptions. Refer to [Splunk props.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.0-configuration-file-reference/props.conf).

## Expected evidence

| Query | Expected qualifying group | Peak window count |
| --- | --- | --- |
| `brute_force.spl` | `gateway-01 / 203.0.113.10 / admin` | 8 failures |
| `password_spray.spl` | `gateway-01 / 198.51.100.23` | 6 accounts |
| `distributed_attempts.spl` | `gateway-01 / service` | 6 failures, 3 sources |

Each query returns qualifying event rows, not one consolidated incident. The first query should yield four rows (failure counts 5–8); the other two should each yield two rows. These expectations are derived from the fixture, pending execution in Splunk. Uploading the file twice changes counts.

`streamstats time_window=5m` uses event-relative rolling windows after ascending timestamp sorting. A fixed `bin _time span=5m` query has different boundary behavior. Resource limits can cap retained events; validate high-volume behavior and exact boundary/tie semantics before production use. See [streamstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/streamstats). Named captures are described in [rex](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/rex).

## Investigate success after failures

For the sample, search the same host, account and source for successful authentication after the failure burst and within ten minutes of its last qualifying failure. This search shows the relevant evidence for manual ordering:

```spl
index=ssh_lab sourcetype="bf:ssh" "gateway-01" "admin" "203.0.113.10"
| sort 0 + _time
| table _time _raw
```

The sample contains `Accepted publickey` at 09:06:10 UTC. A public-key success does not establish that a guessed password worked. The Python detector performs the automated burst-to-success correlation; the query above is a manual evidence view.

For real monitoring, first validate on known benign and test events. A candidate schedule is every minute with a ten-minute lookback for five-minute failure rules, adjusted for ingestion latency. Restrict alert results to a new-event interval and suppress duplicates by rule and group. Tune approved-source exclusions and thresholds; the SPL templates do not inherit Python `--allow` settings. Set alerts to review only until false positives and collection gaps are understood. No alert or blocking action is deployed by this repository.
