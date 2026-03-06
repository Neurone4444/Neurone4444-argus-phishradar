
#!/usr/bin/env python3
"""
ARGUS Layout Cluster Tool
Finds reused phishing kit layouts by clustering layout_fingerprint JSON files.

Usage:
    python argus_layout_cluster.py --dir radar_out

It scans for files like:
    layout_fingerprint_*.json

and groups them by identical fingerprint hashes.
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict

def load_fingerprints(directory: Path):
    clusters = defaultdict(list)

    for file in directory.rglob("layout_fingerprint_*.json"):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        fp = data.get("layout_fingerprint") or data.get("fingerprint")
        url = data.get("url") or "unknown"

        if fp:
            clusters[fp].append({
                "url": url,
                "file": str(file)
            })

    return clusters


def print_clusters(clusters):
    print("\n=== ARGUS Layout Fingerprint Clusters ===\n")

    for fp, entries in clusters.items():
        if len(entries) < 2:
            continue

        print(f"Fingerprint: {fp}")
        print(f"Occurrences: {len(entries)}")

        for e in entries:
            print(f"  - {e['url']}  ({e['file']})")

        print("-" * 60)


def main():
    parser = argparse.ArgumentParser(description="Cluster ARGUS layout fingerprints")
    parser.add_argument("--dir", required=True, help="Directory containing Argus outputs")
    args = parser.parse_args()

    directory = Path(args.dir)

    if not directory.exists():
        print("Directory not found:", directory)
        return

    clusters = load_fingerprints(directory)

    if not clusters:
        print("No fingerprints found.")
        return

    print_clusters(clusters)


if __name__ == "__main__":
    main()
