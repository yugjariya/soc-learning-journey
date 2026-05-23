# Log Analysis Basics

## Objective
The objective of this lab was to understand how log entries work and how SOC Analysts analyze logs to detect suspicious activity and security events.

---

# What is Log Analysis?

Log analysis is the process of reviewing and investigating system and network logs to identify:
- Security incidents
- Failed login attempts
- Suspicious activity
- Malware behavior
- Unauthorized access

---

# 10 Sample Log Entries with Analysis

---

## 1. Failed SSH Login Attempt

```bash
May 13 10:21:45 kali sshd[2045]: Failed password for root from 192.168.1.15 port 51422 ssh2
