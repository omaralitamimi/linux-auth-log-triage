"""Parse common OpenSSH authentication events from saved Linux auth logs."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

PATTERNS = {
    "failure": re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
    "success": re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
}


def triage(text: str) -> dict:
    events = []
    failures = Counter()
    for line in text.splitlines():
        for kind, pattern in PATTERNS.items():
            match = pattern.search(line)
            if match:
                event = {"type": kind, **match.groupdict(), "raw": line}
                events.append(event)
                if kind == "failure":
                    failures[event["ip"]] += 1
                break
    return {"event_count": len(events), "failed_by_ip": dict(failures.most_common()), "events": events}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    print(json.dumps(triage(args.log.read_text(encoding="utf-8")), indent=2))


if __name__ == "__main__":
    main()
