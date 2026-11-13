"""Cross-reference raw scan results and classify each port by confidence."""
from collections import defaultdict

_LABELS = {
    "open": "Open", "closed": "Closed", "filtered": "Filtered",
    "unfiltered": "Unfiltered", "open|filtered": "Open|Filtered",
    "closed|filtered": "Closed|Filtered",
}


def consolidate(raw_results):
    """Turn evasion.run() output into a structured report.

    Returns {by_scan, consolidated, firewall, summary}.
    """
    by_scan = []
    stats = defaultdict(lambda: defaultdict(int))  # port -> state -> count
    protos = defaultdict(set)                       # port -> {proto}
    totals = defaultdict(int)                       # port -> total observations
    ack = {}                                        # port -> state (ACK scan)

    for result in raw_results:
        if not isinstance(result, dict):
            continue
        cmd = result.get("command", "Unknown")
        if "error" in result:
            by_scan.append({"command": cmd, "error": result["error"]})
            continue

        rows = []
        scan = result.get("result", {}).get("scan", {})
        for host in scan:
            for proto in scan[host].all_protocols():
                for port, pinfo in scan[host][proto].items():
                    state = pinfo.get("state", "unknown")
                    reason = pinfo.get("reason", "unknown").capitalize()
                    totals[port] += 1
                    protos[port].add(proto)
                    stats[port][state] += 1
                    if "-sA" in cmd:
                        ack[port] = state
                    rows.append({
                        "port": port, "proto": proto, "state": state,
                        "label": _LABELS.get(state, state.capitalize()),
                        "reason": reason,
                    })
        by_scan.append({"command": cmd, "ports": rows})

    consolidated, opens, undetermined = [], [], []
    for port in sorted(stats):
        total = totals[port]
        if total == 0:
            continue
        s = stats[port]
        proto_str = ", ".join(sorted(protos[port]))

        if s.get("open", 0) > 0:
            style, label = "open", "OPEN"
            detail = f"{s['open']}/{total} scans confirmed ({s['open'] / total * 100:.0f}%)"
            opens.append(port)
        elif s.get("open|filtered", 0) > 0 and s.get("filtered", 0) == 0:
            style, label = "undetermined", "UNDETERMINED"
            detail = "Ambiguous FIN/NULL/UDP scan - may be open"
            undetermined.append(port)
        elif s.get("closed", 0) > 0:
            style, label = "closed", "CLOSED"
            detail = f"{s['closed']}/{total} scans received RST/Unreach"
        else:
            style, label = "filtered", "FILTERED"
            detail = f"{s.get('filtered', 0)}/{total} scans blocked"

        consolidated.append({
            "port": port, "protos": proto_str, "style": style,
            "label": label, "detail": detail,
        })

    firewall = {
        "allows": [p for p, st in ack.items() if st == "unfiltered"],
        "closed": [p for p, st in ack.items() if st == "closed"],
        "blocks": [p for p, st in ack.items() if st == "filtered"],
    }

    return {
        "by_scan": by_scan,
        "consolidated": consolidated,
        "firewall": firewall,
        "summary": {"open": opens, "undetermined": undetermined},
    }
