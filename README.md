# Layer 2 Network Discovery & MITM ARP Spoofer

> **EDUCATIONAL DISCLAIMER:** > This tool was developed strictly for educational purposes, authorized network auditing, and demonstrating vulnerabilities within the OSI model. Do not use this software against networks or devices you do not own or do not have explicit, written permission to test. The author assumes no liability and is not responsible for any misuse or damage caused by this program.

## Overview
A native Linux network utility built in Python. This tool bypasses standard ICMP blocking by operating directly at Layer 2, utilizing raw Ethernet frames to dynamically map local subnets and execute a Man-in-the-Middle (MITM) ARP poisoning attack. 

It was engineered with strict defensive programming practices, utilizing modern Python type-hinting, tuple unpacking, and error handling.

## Features
* **Dynamic Subnet Calculation:** Utilizes the native Linux `ip` suite to dynamically calculate the active IPv4 CIDR block without relying on deprecated `ifconfig` logic or hardcoded IPs.
* **Unblockable Host Discovery:** Sends crafted `ff:ff:ff:ff:ff:ff` Ethernet broadcasts to bypass strict host firewalls (like Windows Defender) that drop standard Layer 3 ping sweeps.
* **Targeted Interception:** Executes continuous, state-overwriting ARP replies to both a selected target and the default gateway, safely routing traffic through the attacking machine by manipulating the Linux kernel's `ip_forward` parameters.
* **Graceful Termination:** Catches `KeyboardInterrupt` signals to automatically restore the kernel's IP forwarding state and prevent lingering network outages.
* **Clean CLI Interface:** Features a formatted, defensively programmed command-line interface that handles empty network lists and invalid user inputs seamlessly.

## Architecture & Dependencies
* **Language:** Python 3
* **Core Library:** [Scapy](https://scapy.net/) (for packet forging and network parsing)
* **OS Compatibility:** Strictly Linux (requires `root` execution to manipulate raw network sockets and kernel parameters).

## Usage
1. Clone the repository and install the required dependencies:
   ```bash
   sudo apt update
   sudo apt install python3-scapy
