# Salvo

Network discovery and firewall/IDS evasion scanner. Salvo wraps `nmap` with a
structured, 5-phase evasion workflow and a consolidated analysis that
cross-references every scan to classify each port by confidence.

Salvo is a ground-up rewrite of my first project:
the same evasion engine, rebuilt as a proper Python package with a cleaner
CLI and no raw nmap arguments to memorize.

> **Authorized use only.** Salvo performs active scanning and firewall/IDS
> evasion. Run it **only** against systems you own or have explicit written
> permission to test. Unauthorized scanning is illegal in most jurisdictions.
> You are solely responsible for how you use this tool.

## Features

- **Subnet discovery**: ping sweep that lists active hosts, sorted by IP.
- **Direct host scan**: fast/top/full/web presets, no need to remember nmap flags.
- **5-phase evasion engine**: progressively aggressive techniques to probe
  hosts behind a firewall or IDS.
- **Subnet-based decoys**: decoy IPs drawn from the target's own `/24`, more
  convincing than random ones.
- **Consolidated analysis**: every scan is cross-referenced and each port is
  classified Open / Closed / Filtered / Unfiltered / Undetermined, with a
  confidence figure.
- **Firewall mapping**: an ACK scan reveals which ports the firewall lets through.

## Evasion phases

| Phase | Name | Technique |
|-------|------|-----------|
| 1 | Firewall Mapping | ACK + Window scans, passive and rarely logged |
| 2 | SYN Stealth | Slow SYN with human-like timing and jitter |
| 3 | Bypass Techniques | Source-port spoofing (53/443), FIN scan, bad checksum |
| 4 | Controlled Brute Force | Double fragmentation, MTU 16, high-rate SYN |
| 5 | UDP Scan | Common UDP ports with payload padding |

## Installation

Requires Python 3.8+ and `nmap` installed on the system.

```bash
# system nmap
sudo apt install nmap        # Debian/Ubuntu
sudo pacman -S nmap          # Arch

# install Salvo
git clone https://github.com/JohnnYoru/Salvo.git
cd Salvo
pip install .
```

This installs the `salvo` command. For development, use `pip install -e .`.

## Usage

Most capabilities (SYN scan, decoys, fragmentation) need raw sockets, so run
with `sudo`:

```bash
salvo                        # discover the local /24, then scan a chosen host
salvo 192.168.1.0/24         # discover a specific subnet
salvo 192.168.1.10           # scan a single host directly
salvo -x 10.0.0.5            # run the 5-phase evasion straight against a target
salvo 10.0.0.5 --scan full   # full port scan (all 65535 ports)
salvo -x 10.0.0.5 --phases 1,2,5
```

### Options

| Flag | Description |
|------|-------------|
| `target` | IP, hostname or CIDR. A CIDR (or no target) runs discovery; a single host is scanned directly. |
| `-x, --evade TARGET` | Skip discovery and run the 5-phase evasion directly. |
| `--scan {fast,top,full,web}` | Port-scan preset for the direct scan (default: `fast`). |
| `--ports SPEC` | Explicit ports, overrides `--scan` (e.g. `80,443` or `1-1000`). |
| `--nmap ARGS` | Raw nmap arguments for full control. |
| `--phases LIST` | Restrict evasion to specific phases, e.g. `1,2,5`. |
| `-v, --verbose` | Show MAC and vendor during discovery. |
| `--no-color` | Disable colored output. |

### Port status legend

| Symbol | Meaning |
|--------|---------|
| `●` | Open: confirmed by SYN-ACK |
| `○` | Closed: received RST |
| `·` | Filtered: no response (likely dropped by firewall) |
| `◑` | Unfiltered: ACK scan passed, state unknown |
| `◐` | Undetermined: ambiguous result (UDP / FIN scan) |

## License

Released under the [MIT License](LICENSE).
