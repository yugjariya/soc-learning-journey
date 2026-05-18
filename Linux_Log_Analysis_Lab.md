# Linux Log Analysis Lab - auth.log Investigation

## Objective
The objective of this lab was to analyze Linux authentication logs using `auth.log` and identify important security-related events.

---

# What is auth.log?
`auth.log` stores authentication and authorization related events in Linux systems.

It helps SOC Analysts monitor:
- Login attempts
- Failed logins
- SSH activity
- Sudo usage
- User authentication events

---

# Tools Used
- Kali Linux / Ubuntu
- Terminal
- auth.log
- grep command

---

# Commands Used

## View auth.log
```bash
cat /var/log/auth.log
