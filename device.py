from dataclasses import dataclass


@dataclass
class Device:
    """A single host discovered on the local network."""
    ip: str
    mac: str
    vendor: str = 'Unknown'
    hostname: str = ''
    role: str = 'host'          # 'host' | 'gateway' | 'self'
    status: str = 'online'      # 'online' | 'cut' | 'throttled'
    packets: int = 0            # spoof packets sent at this target
    throttle: int = 0           # % of packets dropped when status == 'throttled'

    @property
    def is_target(self) -> bool:
        """Only ordinary hosts may be cut (never the router or this machine)."""
        return self.role == 'host'
