"""The 5-phase firewall/IDS evasion engine."""
import random
import threading
from time import sleep

import nmap

# Reusable port sets: legacy, modern web/dev, databases, remote access.
PORTS_TOP    = "21,22,23,25,53,80,110,135,139,143,443,445,3000,3306,3389,5432,5900,6379,8000,8080,8443,27017"
PORTS_WEB    = "80,443,3000,3001,4200,5000,5173,8000,8080,8443,9000"
PORTS_DEV    = "3000,3001,4200,5000,5173,8000,8080,9000"
PORTS_REMOTE = "22,23,3389,5900"
PORTS_DB     = "1433,3306,5432,6379,27017"


def _decoys(ip):
    """Decoys from the target's own /24 - more convincing than RND."""
    octets = ip.split(".")
    if len(octets) != 4:
        return "RND:5", "RND:5,ME,RND:3"
    base = ".".join(octets[:3])
    pool = [f"{base}.{i}" for i in range(1, 255) if f"{base}.{i}" != ip]
    local = ",".join(random.sample(pool, min(5, len(pool))))
    mixed = f"{local},ME,{','.join(random.sample(pool, min(3, len(pool))))}"
    return local, mixed


def build_phases(ip):
    """Return ordered [(number, name, [nmap_arg_strings])]."""
    local_decoys, mixed_decoys = _decoys(ip)

    phase1 = [  # Passive firewall recon - ACK/Window scans are rarely logged.
        f"-sA -Pn --max-retries 1 -p {PORTS_TOP}",
        f"-sW -Pn --max-retries 1 -p {PORTS_WEB}",
    ]
    phase2 = [  # SYN stealth with human-like timing.
        f"-sS -Pn -T2 --max-retries 2 --scan-delay 800ms --max-scan-delay 2s -p {PORTS_TOP} --ttl 64",
        f"-sS -Pn -f -T2 --max-retries 1 --data-length 24 -D {mixed_decoys} -p {PORTS_WEB}",
    ]
    phase3 = [  # Bypass techniques for stateless firewalls.
        f"-sS -Pn -g 53 --max-retries 1 -p {PORTS_REMOTE},{PORTS_DB}",
        f"-sS -Pn -g 443 --max-retries 1 -p {PORTS_REMOTE},{PORTS_DEV}",
        f"-sF -Pn --max-retries 1 -p {PORTS_WEB},22",
        "-sS -Pn --badsum --max-retries 1 -p 80,443,8080",
    ]
    phase4 = [  # Controlled brute force - volume/timing.
        f"-sS -f -f -n -p {PORTS_WEB},22,3389",
        f"-sS --min-rate 5000 -T4 -p {PORTS_TOP}",
        f"-sS -Pn -f --mtu 16 -D {local_decoys} --data-length 32 --scan-delay 500ms -p {PORTS_WEB}",
    ]
    phase5 = [  # UDP last - slow and noisy.
        "-sU -Pn --max-retries 1 --host-timeout 60s "
        "-p 53,67,88,123,137,138,139,143,161,162,500,5353 --data-length 64",
    ]
    return [
        (1, "Firewall Mapping", phase1),
        (2, "SYN Stealth", phase2),
        (3, "Bypass Techniques", phase3),
        (4, "Controlled Brute Force", phase4),
        (5, "UDP Scan", phase5),
    ]


def run(ip, only_phases=None):
    """Run the selected phases and return raw [{command, result|error}].

    Phases run sequentially (with jitter between them); scans within a phase
    run in parallel pairs.
    """
    phases = build_phases(ip)
    if only_phases:
        phases = [p for p in phases if p[0] in only_phases]

    results = []

    def scan_task(args, sink):
        try:
            nm = nmap.PortScanner()
            sink.append({"command": args, "result": nm.scan(ip, arguments=args)})
        except Exception as e:  # nmap/network errors are per-scan, keep going
            sink.append({"command": args, "error": str(e)})

    for idx, (_, _, commands) in enumerate(phases):
        for i in range(0, len(commands), 2):
            threads, batch = [], []
            for cmd in commands[i:i + 2]:
                t = threading.Thread(target=scan_task, args=(cmd, batch))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            results.extend(batch)
        if idx < len(phases) - 1:
            sleep(random.uniform(2.5, 5.5))  # jitter breaks IDS correlation

    return results
