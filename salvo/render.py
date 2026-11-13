"""Terminal output: colors, spinner and the scan report layout."""
import sys
import threading
from time import sleep
from contextlib import contextmanager

from colorama import init as _colorama_init, Fore, Style

_colorama_init()


class _Palette:
    """Color tokens that collapse to empty strings when color is disabled."""

    _NAMES = {
        "CYAN": Fore.CYAN, "GREEN": Fore.GREEN, "YELLOW": Fore.YELLOW,
        "RED": Fore.RED, "LCYAN": Fore.LIGHTCYAN_EX, "LBLUE": Fore.LIGHTBLUE_EX,
        "LYELLOW": Fore.LIGHTYELLOW_EX, "GREY": Fore.LIGHTBLACK_EX,
        "BRIGHT": Style.BRIGHT, "DIM": Style.DIM, "RESET": Style.RESET_ALL,
    }

    def __init__(self, enabled=True):
        for name, code in self._NAMES.items():
            setattr(self, name, code if enabled else "")


P = _Palette(True)

# State -> (palette attr, icon). Shared by per-scan and consolidated views.
STATE_STYLE = {
    "open":          ("GREEN", "●"),
    "closed":        ("YELLOW", "○"),
    "filtered":      ("GREY", "·"),
    "open|filtered": ("LYELLOW", "◐"),
    "unfiltered":    ("LCYAN", "◑"),
    "undetermined":  ("LYELLOW", "◐"),
}


def set_color(enabled):
    global P
    P = _Palette(enabled)


def _style(key):
    attr, icon = STATE_STYLE.get(key, ("GREY", "·"))
    return getattr(P, attr), icon


def rule(width=58):
    return f"{P.GREY}  {'─' * width}{P.RESET}"


def heading(text):
    print(f"\n{P.CYAN}{P.BRIGHT}  {text}{P.RESET}")
    print(rule())


def banner(subtitle, local_ip, target=None):
    print()
    print(f"{P.CYAN}{P.BRIGHT}  Salvo{P.RESET}{P.DIM} · {subtitle}{P.RESET}")
    print(f"  {P.GREY}Local IP:{P.RESET} {P.LCYAN}{local_ip}{P.RESET}")
    if target:
        print(f"  {P.GREY}Target:  {P.RESET} {target}")


def info(arrow_text):
    print(f"  {P.CYAN}↪{P.RESET} {arrow_text}")


def warn(text):
    print(f"  {P.YELLOW}!{P.RESET} {text}")


def ok(text):
    print(f"  {P.GREEN}✓{P.RESET} {text}")


def error(text):
    print(f"  {P.RED}✗{P.RESET} {text}")


def host_list(hosts, verbose=False):
    ok(f"{len(hosts)} active host(s):\n")
    for i, h in enumerate(hosts):
        line = (f"    {P.GREY}[{i}]{P.RESET} "
                f"{P.LCYAN}{h['hostname']}{P.RESET} {P.DIM}({h['ip']}){P.RESET}")
        if verbose:
            line += f" {P.DIM}{h.get('mac', '')} {h.get('vendor', '')}{P.RESET}"
        print(line)


def port_list(ports):
    ok(f"{len(ports)} open port(s):\n")
    for i, port in enumerate(ports):
        print(f"    {P.GREY}[{i}]{P.RESET} {P.GREEN}{port}{P.RESET}")


@contextmanager
def spinner():
    """Animated loader; always restores the cursor on exit."""
    done = threading.Event()
    frames = ["  [     ]", "  [=    ]", "  [==   ]", "  [===  ]", "  [==== ]",
              "  [=====]", "  [ ====]", "  [  ===]", "  [   ==]", "  [    =]"]

    def spin():
        while not done.is_set():
            for frame in frames:
                if done.is_set():
                    break
                sys.stdout.write(f"\r{P.CYAN}{frame}{P.RESET}")
                sys.stdout.flush()
                sleep(0.1)

    sys.stdout.write("\033[?25l")  # hide cursor
    sys.stdout.flush()
    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        yield
    finally:
        done.set()
        t.join()
        sys.stdout.write("\r\033[K\033[?25h")  # clear line + show cursor
        sys.stdout.flush()


def report(analysis):
    """Render the full evasion report from analysis.consolidate() output."""
    heading("RESULTS BY SCAN")
    for scan in analysis["by_scan"]:
        short = scan["command"][:55] + ("..." if len(scan["command"]) > 55 else "")
        print(f"\n  {P.LBLUE}▸{P.RESET} {P.DIM}{short}{P.RESET}")
        if "error" in scan:
            print(f"    {P.RED}✗ Error: {scan['error']}{P.RESET}")
            continue
        for row in scan["ports"]:
            color, icon = _style(row["state"])
            print(f"    {color}{icon} {row['port']:>5}/{row['proto']:<3}{P.RESET}  "
                  f"{color}{row['label']:<18}{P.RESET}{P.DIM} {row['reason']}{P.RESET}")

    heading("CONSOLIDATED ANALYSIS")
    for row in analysis["consolidated"]:
        color, icon = _style(row["style"])
        print(f"  {color}{icon} Port {row['port']:>5}/{row['protos']:<8}{P.RESET}  "
              f"{color}{row['label']:<14}{P.RESET}{P.DIM}  {row['detail']}{P.RESET}")

    fw = analysis["firewall"]
    if fw["allows"] or fw["blocks"] or fw["closed"]:
        heading("FIREWALL MAPPING")
        print(f"{P.DIM}  (ACK scan reveals which ports the firewall lets through){P.RESET}")
        if fw["allows"]:
            print(f"  {P.LCYAN}↪ Firewall ALLOWS:{P.RESET}  {_joined(fw['allows'])}")
        if fw["closed"]:
            print(f"  {P.YELLOW}↪ Allowed but no service:{P.RESET}  {_joined(fw['closed'])}")
        if fw["blocks"]:
            print(f"  {P.GREY}↪ Firewall BLOCKS:{P.RESET}  {_joined(fw['blocks'])}")

    heading("SUMMARY")
    opens = analysis["summary"]["open"]
    undet = analysis["summary"]["undetermined"]
    if opens:
        print(f"  {P.GREEN}✓{P.RESET} {len(opens)} open port(s): {P.GREEN}{_joined(opens)}{P.RESET}")
    else:
        warn("No ports confirmed as open")
    if undet:
        print(f"  {P.LYELLOW}?{P.RESET} {len(undet)} undetermined port(s): "
              f"{P.LYELLOW}{_joined(undet)}{P.RESET}")
    print(f"\n{rule()}")
    print(f"{P.CYAN}  Scan complete.{P.RESET}\n")


def _joined(ports):
    return ", ".join(str(p) for p in sorted(ports))
