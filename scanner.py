"""Network discovery and gateway/MAC helpers.

Discovery uses a ping-sweep followed by a read of the OS ARP table. On Wi-Fi
this is far more reliable than a scapy ARP broadcast sweep, because Wi-Fi
adapters/APs filter the raw layer-2 broadcast frames scapy injects. The ping
sweep makes the OS resolve each host's MAC into its ARP cache (this works even
for hosts that block ICMP, as long as they answer ARP), which we then read.
"""
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import vendor
from device import Device
from var import system
from scapy.all import get_working_ifaces
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

BROADCAST = 'ff:ff:ff:ff:ff:ff'
_NOEXEC = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
if system == 'windows':
    _NOEXEC['stdin'] = subprocess.DEVNULL


def self_ip() -> str:
    """Best-effort local IP of the interface used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_iface(ip: str | None = None):
    """Return the scapy interface whose address matches our LAN IP (or None)."""
    ip = ip or self_ip()
    return next((i for i in get_working_ifaces() if i.ip == ip), None)


def get_gateway_ip() -> str:
    if system == 'windows':
        out = subprocess.check_output(
            ['route', 'print', '0.0.0.0'],
            stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).decode('latin-1')
        m = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)', out)
    else:
        out = subprocess.check_output(['ip', 'route'], stderr=subprocess.DEVNULL).decode('utf-8', 'replace')
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
    if not m:
        raise RuntimeError('Could not determine the default gateway.')
    return m.group(1)


def _ping(ip: str) -> None:
    if system == 'windows':
        cmd = ['ping', '-n', '1', '-w', '600', ip]
    else:
        cmd = ['ping', '-c', '1', '-W', '1', ip]
    try:
        subprocess.run(cmd, **_NOEXEC)
    except Exception:
        pass


def _ping_sweep(prefix: str) -> None:
    """Ping every host in the /24 to populate the OS ARP table."""
    ips = [f'{prefix}.{i}' for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(_ping, ips))


def _read_arp_table(prefix: str) -> dict[str, str]:
    """Parse `arp -a` into {ip: mac} for the given /24 prefix."""
    try:
        raw = subprocess.check_output(['arp', '-a'], stderr=subprocess.DEVNULL)
    except Exception:
        return {}
    out = raw.decode('latin-1', 'replace')
    entries: dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})', line)
        if not m:
            continue
        ip, mac = m.group(1), m.group(2).replace('-', ':').lower()
        if not ip.startswith(prefix + '.'):
            continue
        if ip.endswith('.255') or ip.endswith('.0'):
            continue
        if mac in (BROADCAST, '00:00:00:00:00:00') or mac.startswith(('01:00:5e', '33:33', 'ff:ff')):
            continue
        entries[ip] = mac
    return entries


def get_mac(ip: str, timeout: float = 2.0) -> str | None:
    """Resolve a single IP's MAC: try the ARP table first, then active ARP."""
    prefix = ip.rsplit('.', 1)[0]
    cached = _read_arp_table(prefix).get(ip)
    if cached:
        return cached
    _ping(ip)
    cached = _read_arp_table(prefix).get(ip)
    if cached:
        return cached
    iface = get_iface()
    ans = srp(Ether(dst=BROADCAST) / ARP(pdst=ip), timeout=timeout, verbose=False, iface=iface)[0]
    return ans[0][1].hwsrc.lower() if ans else None


def _hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ''


def _resolve_hostnames(ips: list[str]) -> dict[str, str]:
    """Reverse-DNS many IPs at once with a short timeout (hosts without a PTR
    record otherwise block for seconds each, making a scan crawl)."""
    if not ips:
        return {}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(1.0)
    try:
        with ThreadPoolExecutor(max_workers=32) as ex:
            return dict(zip(ips, ex.map(_hostname, ips)))
    finally:
        socket.setdefaulttimeout(old)


def scan(timeout: float = 2.0, passes: int = 1) -> tuple[list[Device], str, str]:
    """Discover hosts on the local /24 via ping-sweep + ARP table.

    Returns (devices, self_ip, gateway_ip). Devices are tagged with their role
    (gateway / self / host) and enriched with vendor + hostname.

    ``passes`` runs the sweep multiple times a few seconds apart and unions the
    results — a "deep scan". Devices that sleep/idle (phones, IoT) answer ARP
    only intermittently, so extra passes catch more of them. One pass is fast
    (~6s); three passes are more thorough (~15s).
    """
    my_ip = self_ip()
    try:
        gw_ip = get_gateway_ip()
    except Exception:
        gw_ip = ''
    prefix = my_ip.rsplit('.', 1)[0]

    passes = max(1, passes)
    table: dict[str, str] = {}
    for p in range(passes):
        _ping_sweep(prefix)
        table.update(_read_arp_table(prefix))  # union across passes
        if p < passes - 1:
            time.sleep(2.0)  # give idle devices a chance to wake between passes

    # Ensure our own machine is always listed.
    if my_ip not in table:
        iface = get_iface(my_ip)
        table[my_ip] = (iface.mac.lower() if iface and iface.mac else '')

    host_ips = [ip for ip in table if ip not in (gw_ip, my_ip)]
    names = _resolve_hostnames(host_ips)

    devices: list[Device] = []
    for ip, mac in table.items():
        d = Device(ip=ip, mac=mac)
        d.vendor = vendor.lookup(mac)
        if ip == gw_ip:
            d.role = 'gateway'
            d.hostname = 'gateway / router'
        elif ip == my_ip:
            d.role = 'self'
            d.hostname = socket.gethostname()
        else:
            d.hostname = names.get(ip, '')
        devices.append(d)

    devices.sort(key=lambda d: tuple(int(o) for o in d.ip.split('.')))
    return devices, my_ip, gw_ip
