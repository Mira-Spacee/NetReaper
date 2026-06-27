"""Cyber-themed terminal UI (rich). Redraws in place — no scrolling spam."""
import sys

# Windows consoles default to a legacy code page (cp1252) that cannot encode the
# UI glyphs, which would crash rendering. Force UTF-8 before anything prints.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8')
    except Exception:
        pass

from pyfiglet import Figlet
from rich.align import Align
from rich.box import HEAVY, ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

ACCENT = 'bright_green'
CYAN = 'bright_cyan'
DANGER = 'bright_red'
DIM = 'grey42'
WARN = 'bright_yellow'

console = Console()
_fig = Figlet(font='slant')


def _banner() -> Text:
    art = _fig.renderText('NetReaper').rstrip('\n')
    t = Text(art, style=f'bold {ACCENT}')
    t.append('\n  >> LAN ARP MITM CONSOLE //  authorized use only <<', style=f'italic {DIM}')
    return t


def _status_cell(d) -> Text:
    if d.role == 'gateway':
        return Text('◆ ROUTER', style=f'bold {CYAN}')
    if d.role == 'self':
        return Text('★ THIS PC', style=f'bold {WARN}')
    if d.status == 'cut':
        return Text('✖ CUT', style=f'bold {DANGER}')
    return Text('● ONLINE', style=f'bold {ACCENT}')


def _device_table(state) -> Table:
    table = Table(box=ROUNDED, border_style=ACCENT, header_style=f'bold {CYAN}',
                  expand=True, pad_edge=False)
    table.add_column('#', justify='right', style=DIM, width=3)
    table.add_column('IP ADDRESS', style=CYAN, no_wrap=True)
    table.add_column('MAC', style='white', no_wrap=True)
    table.add_column('VENDOR', style=ACCENT)
    table.add_column('HOSTNAME', style=DIM)
    table.add_column('PKTS', justify='right', style=DANGER, width=7)
    table.add_column('STATUS', justify='left', no_wrap=True)

    for i, d in enumerate(state.devices, 1):
        row_style = ''
        if d.status == 'cut':
            row_style = 'on grey11'
        table.add_row(
            str(i),
            d.ip,
            d.mac or '—',
            d.vendor,
            (d.hostname[:24] or '—'),
            (str(d.packets) if d.status == 'cut' else '—'),
            _status_cell(d),
            style=row_style,
        )
    if not state.devices:
        table.add_row('', '[dim]no devices — run [bold]scan[/][/]', '', '', '', '', '')
    return table


def _infobar(state) -> Panel:
    cut = sum(1 for d in state.devices if d.status == 'cut')
    line = Text()
    line.append('  IFACE ', style=DIM); line.append(f'{state.iface}', style=CYAN)
    line.append('   YOU ', style=DIM); line.append(f'{state.self_ip}', style=WARN)
    line.append('   GATEWAY ', style=DIM); line.append(f'{state.gateway or "?"}', style=CYAN)
    line.append('   HOSTS ', style=DIM); line.append(f'{len(state.devices)}', style=ACCENT)
    line.append('   CUT ', style=DIM); line.append(f'{cut}', style=DANGER)
    return Panel(line, box=HEAVY, border_style=DIM, padding=(0, 1))


def _help() -> Text:
    t = Text('  COMMANDS  ', style=f'bold {CYAN}')
    for cmd, desc in [
        ('scan', 'rediscover'), ('scan deep', 'thorough'), ('cut <n>', 'kick'),
        ('restore <n>', 'heal'), ('cut all', ''), ('restore all', ''),
        ('help', ''), ('quit', ''),
    ]:
        t.append(f'{cmd}', style=ACCENT)
        if desc:
            t.append(f'·{desc}', style=DIM)
        t.append('  ', style=DIM)
    t.append('\n  selection: ', style=DIM)
    t.append('1   2 3   1+2   1,3   2-4', style=WARN)
    return t


def render(state) -> None:
    console.clear()
    msg = Text()
    if state.message:
        kind, text = state.message
        colour = {'ok': ACCENT, 'error': DANGER, 'warn': WARN}.get(kind, DIM)
        msg = Text(f'  » {text}', style=f'bold {colour}')
    body = Group(
        Align.center(_banner()),
        Text(),
        _infobar(state),
        _device_table(state),
        _help(),
        msg,
    )
    console.print(body)


def prompt() -> str:
    console.print(Text('\n  netreaper ', style=f'bold {ACCENT}'), end='')
    console.print(Text('> ', style=f'bold {CYAN}'), end='')
    try:
        return input().strip()
    except EOFError:
        return 'quit'


def info(text: str, kind: str = 'ok') -> None:
    colour = {'ok': ACCENT, 'error': DANGER, 'warn': WARN}.get(kind, DIM)
    console.print(Text(f'  {text}', style=colour))
