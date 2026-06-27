"""Pre-flight environment checks so the tool fails loudly instead of silently.

The most common reason this tool appears to "do nothing" on Windows is that
scapy cannot inject layer-2 packets because Npcap is not installed (WinPcap is
deprecated and does not work on modern Windows). This module detects that and
prints an actionable message before any scanning/spoofing is attempted.
"""
import os

import ui
from var import system


def _windows_has_npcap() -> bool:
    # Npcap installs its own copy of wpcap.dll under System32\Npcap.
    npcap_dir = os.path.join(os.environ.get('WINDIR', r'C:\Windows'), 'System32', 'Npcap')
    return os.path.isfile(os.path.join(npcap_dir, 'wpcap.dll'))


def check_packet_driver() -> bool:
    """Return True if packet injection should work, else print help and return False."""
    if system == 'windows' and not _windows_has_npcap():
        ui.info('Npcap was not found. Scapy cannot send/receive packets without it,', 'error')
        ui.info('so scanning and ARP-spoofing will silently fail.', 'error')
        ui.info('', 'warn')
        ui.info('Fix: 1) Uninstall WinPcap (deprecated, broken on Win10/11).', 'warn')
        ui.info('     2) Install Npcap from https://npcap.com/#download', 'warn')
        ui.info('        -> tick "Install Npcap in WinPcap API-compatible Mode".', 'warn')
        ui.info('     3) Reboot, then re-run in an Administrator terminal.', 'warn')
        return False
    return True
