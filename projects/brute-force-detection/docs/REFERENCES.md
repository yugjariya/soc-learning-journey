# References and interpretation

Primary documentation consulted on 1 November 2026:

- [Splunk streamstats](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/streamstats): rolling statistics, grouping, time windows and resource limits.
- [Splunk rex](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.3/search-commands/rex): named regular-expression field extraction.
- [Splunk props.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.3/configuration-file-reference/9.3.0-configuration-file-reference/props.conf): event breaking and timestamp configuration.
- [MITRE ATT&CK T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/): repeated guessing and distributed examples. The project's repeated-failure and distributed rules are behavioral approximations.
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/): trying a small password set across multiple accounts. Authentication logs here contain no attempted passwords, so a multi-account pattern is only a spraying hypothesis.
- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/): detection context and mitigation categories.

Technique labels help classify investigation hypotheses. They do not attribute an actor or prove a compromise. A success following failures is a priority for review, not proof of malicious use of a valid account. Splunk queries were reviewed against these references but were not executed against a live SIEM.
