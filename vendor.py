"""Offline MAC-address -> manufacturer lookup.

Uses the bundled IEEE OUI database (``oui.csv``) so vendor names resolve with
no internet connection. Falls back to a small built-in table if the file is
missing, so the tool still shows useful brand names out of the box.
"""
import csv
import os

_OUI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui.csv')

# Tiny fallback for common devices if oui.csv is unavailable.
_FALLBACK = {
    '001CB3': 'Apple', '3C0754': 'Apple', 'F0989D': 'Apple',
    'F4CFA2': 'Espressif', '240AC4': 'Espressif', 'A4CF12': 'Espressif',
    'B827EB': 'Raspberry Pi', 'DCA632': 'Raspberry Pi', 'E45F01': 'Raspberry Pi',
    '50C7BF': 'TP-Link', 'AC84C6': 'TP-Link', 'C46E1F': 'TP-Link',
    '001A11': 'Google', '3C5AB4': 'Google',
    '00166C': 'Samsung', '8425DB': 'Samsung',
    '0050F2': 'Microsoft', '7C1E52': 'Microsoft',
    '001D7E': 'Cisco-Linksys', '88366C': 'Huawei', '286FB9': 'Nokia',
}

# Common corporate suffixes to trim for a tidy display name.
_SUFFIXES = (
    ', Inc.', ' Inc.', ' Inc', ', Ltd.', ' Ltd.', ' Ltd', ' Co., Ltd.',
    ' Co.,Ltd.', ' CO.,LTD.', ' Corporation', ' Corp.', ' Corp',
    ' Technologies', ' Technology', ' Electronics', ', LLC', ' LLC',
    ' GmbH', ' Company', ' Communications', ' Networks',
    ' Foundation', ' Trading', ' International', ' Systems', ' Group',
)

_db: dict[str, str] | None = None


def _normalize(mac: str) -> str:
    return ''.join(c for c in mac.upper() if c in '0123456789ABCDEF')


def _shorten(name: str) -> str:
    name = name.strip()
    changed = True
    while changed:
        changed = False
        for suf in _SUFFIXES:
            if name.lower().endswith(suf.lower()):
                name = name[: -len(suf)].strip()
                changed = True
    return name[:22] if name else 'Unknown'


def _load() -> dict[str, str]:
    global _db
    if _db is not None:
        return _db
    db: dict[str, str] = {}
    if os.path.isfile(_OUI_FILE):
        try:
            with open(_OUI_FILE, newline='', encoding='utf-8', errors='replace') as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 3 and row[1]:
                        db[row[1].upper()] = row[2]
        except Exception:
            db = {}
    _db = db or dict(_FALLBACK)
    return _db


def is_randomized(mac: str) -> bool:
    """True if the MAC is locally administered (the 0x02 bit of the first octet
    is set) — i.e. a privacy/randomized address used by modern phones."""
    norm = _normalize(mac)
    if len(norm) < 2:
        return False
    return bool(int(norm[:2], 16) & 0x02)


def lookup(mac: str) -> str:
    """Return a short manufacturer name for a MAC, or a descriptive fallback."""
    if not mac:
        return 'Unknown'
    name = _load().get(_normalize(mac)[:6])
    if name:
        return _shorten(name)
    return 'Randomized' if is_randomized(mac) else 'Unknown'
