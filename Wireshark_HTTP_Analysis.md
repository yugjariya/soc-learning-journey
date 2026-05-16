# Wireshark HTTP Traffic Analysis

## Objective
The objective of this lab was to capture and analyze HTTP network traffic using Wireshark and understand how data travels across a network.

---

# Tools Used
- Wireshark
- Web Browser
- Internet Connection

---

# What is HTTP?
HTTP (HyperText Transfer Protocol) is used for communication between web browsers and web servers.

Default HTTP Port:
- Port 80

---

# Steps Performed

## Step 1: Started Packet Capture
Opened Wireshark and selected the active network interface to begin capturing packets.

### Screenshot Suggestion
Add screenshot of:
- Wireshark home screen
- Active interface selection

---

## Step 2: Generated HTTP Traffic
Visited websites using HTTP to generate traffic for analysis.

Example:
- http://example.com

### Screenshot Suggestion
Add screenshot of:
- Browser visiting HTTP website
- Packet capture running

---

## Step 3: Applied HTTP Filter
Used the following filter in Wireshark:

``bash
http
