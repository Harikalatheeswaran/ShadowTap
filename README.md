
---
```ascii
  █████████  █████                    █████                             ███████████                    
 ███░░░░░███░░███                    ░░███                             ░█░░░███░░░█                    
░███    ░░░  ░███████    ██████    ███████   ██████  █████ ███ █████   ░   ░███  ░   ██████   ████████ 
░░█████████  ░███░░███  ░░░░░███  ███░░███  ███░░███░░███ ░███░░███        ░███     ░░░░░███ ░░███░░███
 ░░░░░░░░███ ░███ ░███   ███████ ░███ ░███ ░███ ░███ ░███ ░███ ░███        ░███      ███████  ░███ ░███
 ███    ░███ ░███ ░███  ███░░███ ░███ ░███ ░███ ░███ ░░███████████         ░███     ███░░███  ░███ ░███
░░█████████  ████ █████░░████████░░████████░░██████   ░░████░████          █████   ░░████████ ░███████ 
 ░░░░░░░░░  ░░░░ ░░░░░  ░░░░░░░░  ░░░░░░░░  ░░░░░░     ░░░░ ░░░░          ░░░░░     ░░░░░░░░  ░███░░░  
                                                                                              ░███     
                                                                                              █████    
                                                                                             ░░░░░   
```
---

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python version"/>
  <img src="https://img.shields.io/badge/Scapy-blue?style=for-the-badge" alt="Scapy"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-orange?style=for-the-badge" alt="Platforms"/>
</p>

A python based ethical hacking tool to perform pentesting of WiFi networks via simulating Man In The Middle (MITM) attacks. 
- **Local Network ARP Scanner + Simple MITM / Traffic Monitor (Educational PoC)**



**ShadowTap** is an educational network reconnaissance and traffic observation tool that:

- Discovers devices on your local network using **ARP scanning**
- Lets you select a target device
- Can place your machine **between** the router and the selected device (**ARP spoofing**)
- Or monitor traffic between **your own machine and the gateway**
- Shows live packet count or detailed packet summaries
- Saves captured packet summaries to timestamped log files

> **Important**  
> This code is provided **strictly for educational and security research purposes**.  
> Using it on networks without explicit permission is illegal in most jurisdictions.
 --- 

## Features

- Cross-platform (Linux + Windows)
- Beautiful rich console interface (thanks to [rich](https://github.com/Textualize/rich))
- Automatic detection of local subnet & gateway
- ARP-based host discovery
- Two operation modes:
  - **MITM mode** — ARP spoofing (router ↔ target)
  - **Passive monitoring** — your host ↔ gateway
- Live packet statistics or detailed packet view
- Clean logging to file
- Press **ESC** to gracefully stop sniffing

---

## Requirements

- Python 3.8+
- Administrator / root privileges (required for packet crafting & sniffing)

```bash
pip install scapy rich keyboard
```

On **Linux** you usually also need `libpcap-dev` / `libpcap-devel`.

On **Windows** you need [Npcap](https://npcap.com) (not WinPcap).

---

###  Setup Instructions

 - To install all required Python modules automatically, simply run the batch file:

```
install_requirements.bat
```

 - Double-click the file or run it from the command prompt. This will install all necessary dependencies (such as scapy and rich) for ShadowTap.

---

## Usage

```bash
# Recommended: run as administrator / with sudo
sudo python3 shadowtap.py

# or on Windows (cmd or PowerShell as Administrator)
python shadowtap.py
```

1. Tool auto-detects OS and network settings
2. Performs ARP scan → shows list of discovered devices
3. Lets you choose:
   - Your own machine `(Host)` → monitors your ↔ gateway traffic
   - Any other device → performs ARP spoofing (MITM)
4. Starts packet sniffing
5. Press **ESC** to stop

---

## Important Warnings

- **ARP spoofing is easily detectable** by many modern devices, IDS/IPS, and some antivirus solutions.
- Many networks (corporate, public Wi-Fi, modern home routers) use **ARP protection**, **port security**, or **DHCP snooping** → attack will fail silently.
- Running without root/admin → script will crash when trying to send/sniff raw packets.
- This is **not** a production-grade tool — it's an educational demonstration.

---

## Legal & Ethical Note

You may **only** use this software:
- on networks and devices **you own**
- in lab / home environments you fully control
- during authorized security testing / CTF challenges
- for learning purposes in isolated virtual networks

<!--
## Future / Nice-to-have ideas

- [ ] Vendor / OUI lookup for MAC addresses
- [ ] Save results to CSV/JSON
- [ ] Better error handling on Npcap missing
- [ ] Option to forward traffic properly (real transparent proxy)
- [ ] DNS & HTTP request logging (basic DPI)
-->
---

## Disclaimer

**Educational / Research Use Only**  
- Feel free to fork, modify and learn from it.
- Made for security education & red team playgrounds.
- Happy `(ethical)` Hacking!  
