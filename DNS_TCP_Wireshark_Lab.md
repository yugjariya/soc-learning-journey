# DNS & TCP Traffic Analysis Using Wireshark

## Objective
The objective of this lab was to analyze DNS and TCP traffic using Wireshark and understand how devices communicate over a network.

---

# Tools Used
- Wireshark
- Web Brows]er
- Internet Connection



# Introduction

## What is DNS?
DNS (Domain Name System) converts domain names into IP addresses.

Example:
- google.com → IP Address

Default DNS Port:
- Port 53

---

## What is TCP?
TCP (Transmission Control Protocol) is a reliable communication protocol used for data transfer across networks.

Common TCP Ports:
- 80 → HTTP
- 443 → HTTPS
- 22 → SSH

---

# Lab Steps

## Step 1: Started Packet Capture
Opened Wireshark and selected the active network interface.

### Screenshot Suggestion
Add screenshot of:
- Wireshark interface
- Active network adapter

---

## Step 2: Generated DNS Traffic
Visited websites in a browser to create DNS requests.

Example:
- google.com
- github.com

### Screenshot Suggestion
Add screenshot of:
- Browser accessing websites
- Packets being captured

---

## Step 3: Applied DNS Filter
Used the following filter:

```bash
dns
