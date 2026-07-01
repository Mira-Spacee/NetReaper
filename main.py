import re
import time
from dataclasses import dataclass, field

import scanner
import ui
from device import Device
from preflight import check_packet_driver
from spoofer import Spoofer
from var import system


@dataclass
class State:
    devices: list[Device] = field(default_factory=list)
    self_ip: str = ''
    gateway: str = ''
    iface: str = '—'
    spoofer: Spoofer | None = None
    message: tuple[str, str] | None = None


def _is_admin() -> bool:
    if system == 'windows':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    elif system == 'linux':
        import os
        return os.getuid() == 0
    raise NotImplementedError('This OS is not supported.')


def parse_selection(raw: str, count: int) -> list[int] | None:
    """Parse '1', '2 3 4', '1+2', '1,3', '2-4', '1, 3-5 7' into 0-based indices.

    Returns None on malformed input; out-of-range numbers are dropped.
    """
    tokens = re.split(r'[\s,+]+', raw.strip())
    numbers: list[int] = []
    for tok in tokens:
        if not tok:
            continue
        rng = re.fullmatch(r'(\d+)-(\d+)', tok)
        if rng:
            a, b = int(rng.group(1)), int(rng.group(2))
            numbers.extend(range(min(a, b), max(a, b) + 1))
        elif tok.isdigit():
            numbers.append(int(tok))
        else:
            return None
    seen: set[int] = set()
    result: list[int] = []
    for n in numbers:
        i = n - 1
        if 0 <= i < count and i not in seen:
            seen.add(i)
            result.append(i)
    return result


def _resolve(state: State, arg: str):
    """Map a selection arg ('all' or numbers) to a list of Devices, or None."""
    if arg.strip().lower() == 'all':
        return list(state.devices)
    idxs = parse_selection(arg, len(state.devices))
    if idxs is None:
        return None
    return [state.devices[i] for i in idxs]


def do_scan(state: State, deep: bool = False) -> None:
    passes = 3 if deep else 1
    label = 'Deep scanning (3 passes, ~15s)' if deep else 'Scanning the network'
    ui.info(f'{label}...', 'warn')
    devices, my_ip, gw_ip = scanner.scan(passes=passes)
    # carry over the cut status of devices that are still present
    cut_ips = {d.ip for d in state.devices if d.status == 'cut'}
    for d in devices:
        if d.ip in cut_ips:
            d.status = 'cut'
    state.devices = devices
    state.self_ip, state.gateway = my_ip, gw_ip
    state.iface = my_ip
    targets = sum(1 for d in devices if d.is_target)
    kind = 'deep scan' if deep else 'scan'
    state.message = ('ok', f'{kind}: found {len(devices)} device(s) — {targets} targetable.')


def do_cut(state: State, arg: str) -> None:
    targets = _resolve(state, arg)
    if targets is None:
        state.message = ('error', 'Invalid selection. Try e.g. "cut 1+2" or "cut all".')
        return
    started, skipped = 0, 0
    for d in targets:
        if not d.is_target:
            skipped += 1
            continue
        if state.spoofer.start(d):
            started += 1
    parts = [f'Cutting {started} device(s) — they are losing internet now.']
    if skipped:
        parts.append(f'(skipped {skipped} protected: router/this PC)')
    state.message = ('ok' if started else 'warn', ' '.join(parts))


def do_throttle(state: State, arg: str) -> None:
    parts = arg.strip().rsplit(None, 1)  # last token is the percent
    if len(parts) != 2 or not parts[1].isdigit():
        state.message = ('error', 'Usage: throttle <sel> <percent>, e.g. "throttle 1 50".')
        return
    sel, pct = parts[0], int(parts[1])
    if not (1 <= pct <= 99):
        state.message = ('error', 'Percent must be 1–99 (use "cut" for a full 100% block).')
        return
    if not state.spoofer.can_throttle:
        state.message = ('error', 'Throttle unavailable: could not determine our own MAC/gateway MAC.')
        return
    targets = _resolve(state, sel)
    if targets is None:
        state.message = ('error', 'Invalid selection. Try e.g. "throttle 1+2 50".')
        return
    started, skipped = 0, 0
    for d in targets:
        if not d.is_target:
            skipped += 1
            continue
        if state.spoofer.throttle(d, pct):
            started += 1
    parts_msg = [f'Throttling {started} device(s) to drop {pct}% of packets.']
    if skipped:
        parts_msg.append(f'(skipped {skipped} protected: router/this PC)')
    state.message = ('ok' if started else 'warn', ' '.join(parts_msg))


def do_restore(state: State, arg: str) -> None:
    targets = _resolve(state, arg)
    if targets is None:
        state.message = ('error', 'Invalid selection. Try e.g. "restore 1" or "restore all".')
        return
    restored = sum(1 for d in targets if state.spoofer.stop(d))
    state.message = ('ok', f'Restored {restored} device(s) — connectivity returned.')


def _show_help() -> None:
    ui.info('', 'ok')
    ui.info('cut <sel>      kick device(s) off the internet', 'ok')
    ui.info('throttle <sel> <pct>   slow device(s) by dropping <pct>% of packets', 'ok')
    ui.info('restore <sel>  heal device(s) and give internet back', 'ok')
    ui.info('scan           quick re-discovery (~6s, single pass)', 'ok')
    ui.info('scan deep      thorough discovery (~15s, 3 passes, finds idle devices)', 'ok')
    ui.info('cut all / restore all       act on every targetable device', 'ok')
    ui.info('selection examples: 1   2 3 4   1+2   1,3   2-4', 'warn')
    ui.info('quit           restore everything and exit', 'ok')
    input('\n  press Enter to return...')


def main() -> int:
    ui.console.clear()
    ui.render(State())  # quick banner flash
    if not _is_admin():
        ui.info('No admin privileges. Run in an Administrator terminal (Windows) '
                'or with sudo (Linux). Quitting...', 'error')
        return 1
    if not check_packet_driver():
        return 1

    state = State()
    try:
        gw_ip = scanner.get_gateway_ip()
        gw_mac = scanner.get_mac(gw_ip)
        iface = scanner.get_iface()
    except Exception as e:
        ui.info(f'Could not initialise networking: {e}', 'error')
        return 1
    state.spoofer = Spoofer(gw_ip, gw_mac, iface=iface)

    do_scan(state)

    while True:
        ui.render(state)
        raw = ui.prompt()
        if not raw:
            continue
        cmd, _, arg = raw.partition(' ')
        cmd = cmd.lower()

        if cmd in ('q', 'quit', 'exit'):
            break
        elif cmd in ('s', 'scan'):
            do_scan(state, deep=arg.strip().lower() in ('deep', 'd', '3', 'full'))
        elif cmd in ('c', 'cut'):
            do_cut(state, arg)
        elif cmd in ('t', 'throttle'):
            do_throttle(state, arg)
        elif cmd in ('r', 'restore'):
            do_restore(state, arg)
        elif cmd in ('h', 'help', '?'):
            _show_help()
        else:
            state.message = ('error', f'Unknown command: "{cmd}". Type "help".')

    ui.render(state)
    ui.info('Restoring all targets...', 'warn')
    state.spoofer.stop_all(state.devices)
    time.sleep(0.5)
    ui.info('All devices restored. Goodbye.', 'ok')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
