<div align="center">

# ☠️ NetReaper

**An interactive, cyber-themed LAN control console.**
Discover every active device on your network and cut / restore their internet access in real time — all from a live terminal dashboard.

![Python](https://img.shields.io/badge/python-3.10+-2ea44f?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-2ea44f)
![Scapy](https://img.shields.io/badge/built%20with-scapy%20%2B%20rich-2ea44f)
![Use](https://img.shields.io/badge/use-authorized%20%2F%20educational%20only-red)

</div>

> ⚠️ **For authorized, educational use only.** Only run this against a network you **own** or have **explicit written permission** to test. ARP spoofing disrupts other users and is illegal on networks you don't control. This project was built for a cybersecurity course to demonstrate how Layer-2 ARP poisoning works — and how to defend against it.

---

## ✨ What it does

NetReaper performs an **ARP-spoofing (ARP cache poisoning) man-in-the-middle** attack to selectively cut devices off the internet, wrapped in a clean, persistent terminal UI.

```text
                        _   __     __  ____
                       / | / /__  / /_/ __ \___  ____ _____  ___  _____
                      /  |/ / _ \/ __/ /_/ / _ \/ __ `/ __ \/ _ \/ ___/
                     / /|  /  __/ /_/ _, _/  __/ /_/ / /_/ /  __/ /
                    /_/ |_/\___/\__/_/ |_|\___/\__,_/ .___/\___/_/
                                                   /_/
                      >> LAN ARP MITM CONSOLE //  authorized use only <<

┌──────────────────────────────────────────────────────────────────────────────────────────┐
│   IFACE 192.168.0.100   YOU 192.168.0.100   GATEWAY 192.168.0.1   HOSTS 6   CUT 2        │
└──────────────────────────────────────────────────────────────────────────────────────────┘
┌─────┬───────────────┬───────────────────┬────────────┬──────────────┬─────────┬──────────┐
│   # │ IP ADDRESS    │ MAC               │ VENDOR     │ HOSTNAME     │    PKTS │ STATUS   │
├─────┼───────────────┼───────────────────┼────────────┼──────────────┼─────────┼──────────┤
│   1 │ 192.168.0.1   │ de:ad:be:ef:00:01 │ Example Co │ router       │       — │ ◆ ROUTER │
│   2 │ 192.168.0.21  │ 02:00:00:11:22:33 │ Randomized │ phone        │       — │ ● ONLINE │
│   3 │ 192.168.0.37  │ aa:bb:cc:dd:ee:01 │ Acme Inc   │ game-console │     148 │ ✖ CUT    │
│   4 │ 192.168.0.55  │ aa:bb:cc:dd:ee:02 │ Acme Inc   │ ip-camera    │       — │ ● ONLINE │
│   5 │ 192.168.0.100 │ aa:bb:cc:dd:ee:03 │ Example Co │ my-pc        │       — │ ★ THIS PC│
│   6 │ 192.168.0.142 │ 02:00:00:44:55:66 │ Randomized │ smart-tv     │      92 │ ✖ CUT    │
└─────┴───────────────┴───────────────────┴────────────┴──────────────┴─────────┴──────────┘
  COMMANDS  scan  scan deep  cut <n>  restore <n>  cut all  restore all  help  quit
  netreaper >
```

## 🚀 Features

- **🖥️ Live cyber-themed dashboard** — a `rich`-powered table that redraws in place (no scrolling spam). Shows index, IP, MAC, vendor, hostname, packets sent, and live status.
- **🔁 Fully interactive** — cut and restore devices on the fly without restarting. Type a command, watch the table update, type another.
- **🎯 Flexible multi-target selection** — `cut 1`, `cut 2 3 4`, `cut 1+2`, `cut 1,3`, `cut 2-4`, or `cut all`.
- **🔎 Reliable Wi-Fi discovery** — uses a **ping-sweep + OS ARP-table read** instead of a raw scapy broadcast sweep, which Wi-Fi access points silently filter. This is why it finds *all* active devices where naïve scanners find only the router.
- **🌊 Deep scan** — `scan deep` runs three passes and unions the results to catch devices that are asleep/idle on a single pass.
- **🏷️ Vendor & randomization detection** — resolves manufacturer from a bundled offline IEEE OUI database, and flags privacy-randomized MACs (modern phones) as `Randomized` — a built-in lesson on why MAC fingerprinting is unreliable.
- **♻️ Graceful restoration** — on `restore` or `quit`, NetReaper re-advertises the correct ARP mappings so victims regain connectivity **instantly**, instead of waiting for cache timeout.
- **🛡️ Built-in safeguards** — the router and your own machine are flagged and **cannot** be cut by accident.
- **🩺 Pre-flight checks** — detects a missing Npcap driver and tells you exactly how to fix it, instead of failing silently.

## 🧠 How it works (the 30-second version)

Devices on a LAN use **ARP** to map IP addresses to MAC addresses. ARP has no authentication, so any host can send a forged "I am the gateway" reply. NetReaper continuously tells the **target** that *your* MAC is the router, and tells the **router** that *your* MAC is the target. Both now send their traffic to you instead of each other. NetReaper simply doesn't forward it — so the target loses internet. Stop spoofing and re-send the truth, and connectivity returns.

```
   Normal:    [ Target ] ⇄ [ Router ] ⇄ Internet

   Poisoned:  [ Target ] → [ You ] ✖ (dropped)
              [ Router ] → [ You ] ✖ (dropped)
```

## 📦 Requirements

- **Python 3.10+**
- **Windows:** [**Npcap**](https://npcap.com/#download) — install it and tick *"Install Npcap in WinPcap API-compatible Mode"*. (The deprecated WinPcap does **not** work on Windows 10/11.)
- **Linux:** `libpcap` (usually preinstalled).
- Python packages: `scapy`, `rich`, `pyfiglet`.

## 🔧 Installation

```bash
git clone https://github.com/Mira-Spacee/NetReaper.git
cd NetReaper
pip install -r requirements.txt
```

## ▶️ Usage

Run with **administrator / root** privileges (raw packets require it):

```bat
:: Windows — open an Administrator terminal
python main.py
```
```bash
# Linux
sudo python3 main.py
```

### Commands

| Command | Action |
|---|---|
| `scan` | Quick discovery (~6s, single pass) |
| `scan deep` | Thorough discovery (~15s, 3 passes — finds idle devices) |
| `cut <sel>` | Kick the selected device(s) off the internet |
| `restore <sel>` | Heal the selected device(s) and restore access |
| `cut all` / `restore all` | Act on every targetable device |
| `help` | Show the command reference |
| `quit` | Restore everything and exit cleanly |

**Selection syntax:** `1` · `2 3 4` · `1+2` · `1,3` · `2-4`

## ⚖️ Limitations (read before you trust it)

- **Active scanners only see devices that are awake.** A phone with its screen off or an IoT device on a duty cycle may not answer ARP at scan time and will be missed until it wakes. `scan deep` helps, but the **only** source that knows *every* device (including offline ones) is your **router's admin page** (DHCP client list). This is true of *all* active scanners — Fing, nmap, Angry IP Scanner included.
- **Wi-Fi only spoofs Layer-2.** This is ARP/LAN MITM, not an 802.11 deauthentication attack. (A Flipper Zero + Marauder kicks devices via deauth frames — a different mechanism at the radio layer.)
- It operates on your current `/24` subnet only.

## 🗺️ Roadmap

- [ ] `detect` mode — spot when **someone is ARP-spoofing you** (the defensive counterpart)
- [ ] Bandwidth throttling (traffic shaping) instead of a hard cut
- [ ] CLI arguments for headless / scripted use
- [ ] Linux gateway-detection hardening

## 🙏 Credits

NetReaper is an enhanced derivative of the original **[NetCutter by @RostF1rst](https://github.com/RostF1rst/NetCutter)** — full credit to the original author for the foundation. This version adds the interactive `rich` UI, reliable Wi-Fi discovery, vendor/randomization detection, graceful restoration, deep scan, and pre-flight checks.

The original project ships without a license. NetReaper is published in the same spirit for **educational purposes**; please respect the original author's work.

---

<div align="center">
<sub>Built for a cybersecurity course · ARP poisoning is powerful — use it responsibly and legally.</sub>
</div>
