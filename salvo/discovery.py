"""Local network discovery: local IP, reverse DNS and ping sweep."""
import socket

import nmap


def get_local_ip():
    """Best-effort local IP via a dummy UDP connect (no traffic sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("10.254.254.254", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"


def sort_hosts(hosts):
    """Sort host dicts by numeric IP octets (replaces the old ips-sort script)."""
    def key(h):
        try:
            return tuple(int(o) for o in h["ip"].split("."))
        except (ValueError, KeyError):
            return (256,)  # push non-IPv4 to the end
    return sorted(hosts, key=key)


def ping_sweep(network, verbose=False):
    """Return active hosts on `network` (CIDR), sorted by IP."""
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments="-sn")

    hosts = []
    for ip in nm.all_hosts():
        if nm[ip].state() != "up":
            continue
        host = {"ip": ip, "hostname": get_hostname(ip)}
        if verbose:
            host["mac"] = nm[ip]["addresses"].get("mac", "Unknown MAC")
            vendor = nm[ip].get("vendor", {})
            host["vendor"] = next(iter(vendor.values()), "Unknown")
        hosts.append(host)

    return sort_hosts(hosts)
