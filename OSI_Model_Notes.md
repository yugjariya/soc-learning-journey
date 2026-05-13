# OSI Model Notes

# What is OSI Model?
OSI stands for **Open Systems Interconnection**.  
It is a 7-layer model used to understand how data travels from one device to another over a network.

## OSI Model Diagram
![OSI Model Diagram](https://upload.wikimedia.org/wikipedia/commons/8/8d/OSI_Model_v1.svg)

## 7 Layers of OSI Model

| Layer No. | Layer Name | Main Work | Example |
|---|---|---|---|
| 7 | Application | User services | HTTP, FTP, DNS |
| 6 | Presentation | Data format, encryption | SSL/TLS, JPEG |
| 5 | Session | Manages sessions | Login sessions |
| 4 | Transport | End-to-end delivery | TCP, UDP |
| 3 | Network | IP addressing and routing | IP, Router |
| 2 | Data Link | MAC address, frames | Switch, Ethernet |
| 1 | Physical | Bits through cables/signals | Cables, Wi-Fi |

## Easy Trick to Remember
**All People Seem To Need Data Processing**

Application → Presentation → Session → Transport → Network → Data Link → Physical

## SOC Analyst Use
As a future SOC Analyst, OSI helps in understanding:
- Network traffic
- SIEM logs.
- Firewall alerts
- Packet  analysis in Wireshark
- Troubleshooting attacks layer by layer

## Example
If a website is not opening:
- Layer 1: Cable/Wi-Fi issue
- Layer 3: IP/routing issue
- Layer 4: TCP port issue
- Layer 7: HTTP/DNS issue

## My Learning Goal
I am learning the OSI Model to build a strong foundation in networking and cybersecurity.
