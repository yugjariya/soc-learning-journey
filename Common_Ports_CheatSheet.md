# Common Ports Cheat Sheet

## What are Ports?
Ports are communication endpoints used by different network services and applications.

Understanding ports is very important for:
- Network Security
- Threat Detection
- Firewall Monitoring
- SIEM Analysis

---

# Common Network Ports

| Port | Protocol | Service | Purpose |
|------|----------|----------|----------|
| 20/21 | TCP | FTP | File Transfer |
| 22 | TCP | SSH | Secure Remote Login |
| 23 | TCP | Telnet | Remote Login |
| 25 | TCP | SMTP | Sending Emails |
| 53 | TCP/UDP | DNS | Domain Name Resolution |
| 67/68 | UDP | DHCP | Automatic IP Assignment |
| 69 | UDP | TFTP | Simple File Transfer |
| 80 | TCP | HTTP | Websites (Non-Secure) |
| 110 | TCP | POP3 | Receiving Emails |
| 123 | UDP | NTP | Time Synchronization |
| 143 | TCP | IMAP | Email Access |
| 161/162 | UDP | SNMP | Network Monitoring |
| 389 | TCP/UDP | LDAP | Directory Services |
| 443 | TCP | HTTPS | Secure Websites |
| 445 | TCP | SMB | File Sharing |
| 514 | UDP | Syslog | Log Collection |
| 636 | TCP | LDAPS | Secure LDAP |
| 993 | TCP | IMAPS | Secure IMAP |
| 995 | TCP | POP3S | Secure POP3 |
| 1433 | TCP | MSSQL | Microsoft SQL Server |
| 1521 | TCP | Oracle DB | Oracle Database |
| 3306 | TCP | MySQL | MySQL Database |
| 3389 | TCP | RDP | Remote Desktop |
| 5432 | TCP | PostgreSQL | PostgreSQL Database |
| 5900 | TCP | VNC | Remote Access |
| 8080 | TCP | HTTP Alternate | Web Proxy/Web Apps |

---

# Important Ports for SOC Analysts

## Web Traffic
- 80 → HTTP
- 443 → HTTPS

## Remote Access
- 22 → SSH
- 3389 → RDP

## Email
- 25 → SMTP
- 110 → POP3
- 143 → IMAP

## File Sharing
- 21 → FTP
- 445 → SMB

## DNS & Networking
- 53 → DNS
- 67/68 → DHCP

---

# Why Ports Matter in Cybersecurity

SOC Analysts monitor ports to:
- Detect suspicious traffic
- Identify malware communication
- Investigate attacks
- Monitor unauthorized access
- Analyze network logs in SIEM tools

Example:
- Unusual traffic on port 3389 may indicate an RDP attack
- Suspicious DNS traffic on port 53 may indicate malware communication

---

# Quick Tip
Remember:
- HTTP = 80
- HTTPS = 443
- SSH = 22
- DNS = 53
- RDP = 3389

These are commonly asked in SOC Analyst interviews.
