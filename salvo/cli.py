"""Command-line interface and flow orchestration."""
import argparse
import os
import socket
import sys

import nmap

from . import __version__, analysis, discovery, evasion, render

SCAN_PRESETS = {
    "fast": "--top-ports 100",
    "top":  "--top-ports 1000",
    "full": "-p-",
    "web":  "-p 80,443,3000,5000,8000,8080,8443",
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="salvo",
        description="Network discovery and firewall/IDS evasion scanner.",
        epilog="Examples:\n"
               "  salvo                        discover the local /24, then scan a chosen host\n"
               "  salvo 192.168.1.0/24         discover a specific subnet\n"
               "  salvo 192.168.1.10           scan a single host directly\n"
               "  salvo -x 10.0.0.5            run evasion straight against a target\n"
               "  salvo 10.0.0.5 --scan full   full port scan (all 65535 ports)\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?",
                   help="IP, hostname or CIDR. A CIDR (or no target) runs discovery; "
                        "a single host is scanned directly.")
    p.add_argument("-x", "--evade", metavar="TARGET",
                   help="skip discovery and run the 5-phase evasion directly against TARGET")
    p.add_argument("--scan", choices=SCAN_PRESETS, default="fast",
                   help="port-scan preset for the direct scan (default: fast)")
    p.add_argument("--ports", metavar="SPEC",
                   help="explicit ports, overrides --scan (e.g. 80,443 or 1-1000)")
    p.add_argument("--nmap", metavar="ARGS",
                   help="raw nmap arguments for the direct scan (full control)")
    p.add_argument("--phases", metavar="LIST",
                   help="restrict evasion to these phases, e.g. 1,2,5 (default: all)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show MAC and vendor during discovery")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--version", action="version", version=f"salvo {__version__}")
    return p


def _parse_phases(spec):
    if not spec:
        return None
    try:
        return {int(x) for x in spec.split(",") if x.strip()}
    except ValueError:
        render.error(f"Invalid --phases value: {spec!r}")
        sys.exit(2)


def _scan_arguments(args, is_root):
    if args.nmap:
        return args.nmap
    scan_type = "-sS" if is_root else "-sT"
    ports = f"-p {args.ports}" if args.ports else SCAN_PRESETS[args.scan]
    return f"{scan_type} -T4 {ports}"


def _ask_index(prompt, count):
    while True:
        try:
            raw = input(f"\n  {render.P.CYAN}?{render.P.RESET} {prompt}: ")
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)
        try:
            choice = int(raw)
        except ValueError:
            render.warn("Invalid input.")
            continue
        if 0 <= choice < count:
            return choice
        render.warn("Number out of range.")


def run_evasion(ip, only_phases):
    render.banner("evasion", discovery.get_local_ip(),
                  f"{discovery.get_hostname(ip)} ({ip})")
    print()
    print(f"{render.P.CYAN}{render.P.BRIGHT}  Advanced reconnaissance on {ip}{render.P.RESET}")
    print(f"{render.P.GREY}  {len(only_phases) if only_phases else 5} phase(s) · "
          f"firewall and IDS evasion techniques{render.P.RESET}\n")

    with render.spinner():
        raw = evasion.run(ip, only_phases)

    render.report(analysis.consolidate(raw))


def scan_host(ip, args, is_root):
    """Direct port scan; offers evasion fallback, then a TCP connect test."""
    hostname = discovery.get_hostname(ip)
    render.info(f"Scanning ports on {render.P.LCYAN}{hostname}{render.P.RESET} ({ip})")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments=_scan_arguments(args, is_root))
        open_ports = [port
                      for proto in nm[ip].all_protocols()
                      for port, info in nm[ip][proto].items()
                      if info["state"] == "open"]
    except KeyError:
        open_ports = []  # host not in results (down / fully filtered)
    except nmap.PortScannerError as e:
        render.error(f"nmap error: {e}")
        return

    if not open_ports:
        render.warn("No open ports detected.")
        print(f"  {render.P.DIM}Likely a firewall with an active DROP policy.{render.P.RESET}")
        try:
            answer = input(f"\n  {render.P.CYAN}?{render.P.RESET} "
                           f"Run advanced reconnaissance? [Enter/n]: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if answer.strip().lower() in ("", "y"):
            run_evasion(ip, _parse_phases(args.phases))
        return

    render.port_list(open_ports)
    port = open_ports[_ask_index("Select port", len(open_ports))]

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((ip, port))
        render.ok(f"Connection established to {hostname}:{port}")
        print(f"  {render.P.GREY}URL:{render.P.RESET} http://{ip}:{port}")
        client.close()
    except OSError as e:
        render.error(f"Connection error: {e}")


def discover_and_scan(network, args, is_root):
    render.banner("network discovery", discovery.get_local_ip())
    render.info(f"Scanning subnet {network}...")
    with render.spinner():
        hosts = discovery.ping_sweep(network, verbose=args.verbose)

    if not hosts:
        render.warn("No active hosts found.")
        return

    render.host_list(hosts, verbose=args.verbose)
    choice = _ask_index("Select target", len(hosts))
    print()
    scan_host(hosts[choice]["ip"], args, is_root)


def main(argv=None):
    args = build_parser().parse_args(argv)
    render.set_color(not args.no_color and sys.stdout.isatty())
    is_root = os.geteuid() == 0

    if not is_root:
        render.warn("Not running as root; evasion and SYN scans may fail. "
                    "Re-run with sudo for full capability.")

    try:
        if args.evade:
            run_evasion(args.evade, _parse_phases(args.phases))
        elif args.target and "/" not in args.target:
            render.banner("direct scan", discovery.get_local_ip())
            print()
            scan_host(args.target, args, is_root)
        else:
            network = args.target or (discovery.get_local_ip() + "/24")
            discover_and_scan(network, args, is_root)
    except KeyboardInterrupt:
        sys.stdout.write("\033[?25h")  # ensure cursor restored
        render.warn("Interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
