# 🔍 Azzy's  Network Scanner

A fast, lightweight, and professional Network Scanner built with Python and Scapy. This tool allows security enthusiasts and network administrators to discover live hosts and their MAC addresses on a local network using ARP requests.

## ✨ Features
* **Auto-Detection:** Automatically detects your machine's default IP range—no need to type it manually!
* **Manual Targeting:** Allows scanning specific subnets using the `-t` flag.
* **Fast & Stealthy:** Uses ARP packets for rapid discovery compared to standard ICMP pings.
* **Error Handling:** Gracefully handles permission errors and provides user-friendly CLI feedback.

## 🛠️ Prerequisites
* Python 3.x
* Scapy library
* Root/Sudo privileges (required for crafting custom network packets)

## 🚀 Installation
1. Clone this repository:
   ```bash
   git clone [https://github.com/imadaghoukad/Network-Scanner.git](https://github.com/imadaghoukad/Network-Scanner.git)
   cd Network-Scanner
