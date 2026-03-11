#!/usr/bin/env python3
"""
Sync wappalyzer.json with upstream Wappalyzer data from GitHub.

Usage:
    python scripts/sync_wappalyzer.py

This fetches the latest technology definitions from the open-source
Wappalyzer fork (https://github.com/dochne/wappalyzer) and converts
them to our JSON format at data/wappalyzer.json.

After running, rebuild psnet: cargo build
"""

import json
import os
import sys
import urllib.request

# Upstream Wappalyzer technology files
UPSTREAM_BASE = "https://raw.githubusercontent.com/dochne/wappalyzer/main/src/technologies"
TECH_FILES = [chr(c) + ".json" for c in range(ord('a'), ord('z') + 1)]
TECH_FILES.append("_.json")

# Category names from Wappalyzer (id -> label)
CATEGORIES_URL = "https://raw.githubusercontent.com/dochne/wappalyzer/main/src/categories.json"

def fetch_json(url):
    """Fetch JSON from a URL."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "psnet-sync/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  Warning: Could not fetch {url}: {e}", file=sys.stderr)
        return None

def extract_header_sigs(tech_name, tech_data, categories):
    """Extract header-based signatures from a Wappalyzer technology entry."""
    sigs = []

    # Map category IDs to labels
    cats = tech_data.get("cats", [])
    category = "Technology"
    for cat_id in cats:
        cat_id_str = str(cat_id)
        if cat_id_str in categories:
            category = categories[cat_id_str].get("name", "Technology")
            break

    # Extract from "headers" field: {header_name: pattern}
    headers = tech_data.get("headers", {})
    for header_name, pattern in headers.items():
        if isinstance(pattern, str):
            # Remove regex anchors, version groups, etc. for simple substring match
            clean_pattern = clean_wappalyzer_pattern(pattern)
            if clean_pattern is not None:
                sig = {
                    "name": tech_name,
                    "category": category,
                    "header": header_name.lower(),
                }
                if clean_pattern:
                    sig["pattern"] = clean_pattern
                sigs.append(sig)

    # Extract from "meta" field (maps to HTML meta headers)
    meta = tech_data.get("meta", {})
    for meta_name, pattern in meta.items():
        if isinstance(pattern, str):
            clean_pattern = clean_wappalyzer_pattern(pattern)
            if clean_pattern is not None:
                sig = {
                    "name": tech_name,
                    "category": category,
                    "header": f"x-meta-{meta_name.lower()}",
                }
                if clean_pattern:
                    sig["pattern"] = clean_pattern
                sigs.append(sig)

    return sigs

def clean_wappalyzer_pattern(pattern):
    """
    Convert a Wappalyzer regex pattern to a simple substring match.
    Returns None if the pattern is too complex for substring matching.
    Returns empty string if pattern matches any value (header existence check).
    """
    if not pattern:
        return ""

    # Remove version extraction groups: \\;version:\\1
    if "\\;" in pattern:
        pattern = pattern.split("\\;")[0]

    # Remove confidence: \\;confidence:50
    pattern = pattern.strip()

    # Skip patterns with complex regex
    if any(c in pattern for c in ['(', ')', '|', '[', '+', '*', '{', '?', '^', '$']):
        # Try to extract a simple literal if the regex is just "^literal"
        if pattern.startswith('^') and not any(c in pattern[1:] for c in ['(', ')', '|', '[', '+', '*', '{', '?']):
            return pattern[1:].rstrip('$').lower()
        return None

    # Simple literal pattern
    return pattern.lower()

def main():
    output_path = os.path.join(os.path.dirname(__file__), "..", "data", "wappalyzer.json")

    # Load existing signatures to preserve custom ones
    existing = []
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            existing = json.load(f)
        print(f"Loaded {len(existing)} existing signatures")

    # Fetch categories
    print("Fetching Wappalyzer categories...")
    categories = fetch_json(CATEGORIES_URL) or {}

    # Fetch all technology files
    all_sigs = []
    seen = set()

    for tech_file in TECH_FILES:
        url = f"{UPSTREAM_BASE}/{tech_file}"
        print(f"  Fetching {tech_file}...", end=" ")
        data = fetch_json(url)
        if not data:
            print("skipped")
            continue

        count = 0
        for tech_name, tech_data in data.items():
            if not isinstance(tech_data, dict):
                continue
            sigs = extract_header_sigs(tech_name, tech_data, categories)
            for sig in sigs:
                # Dedup by (name, header, pattern)
                key = (sig["name"], sig["header"], sig.get("pattern", ""))
                if key not in seen:
                    seen.add(key)
                    all_sigs.append(sig)
                    count += 1

        print(f"{count} sigs")

    # Also keep any existing signatures that aren't in upstream
    # (custom/manual additions)
    existing_keys = set()
    for sig in existing:
        key = (sig["name"], sig["header"], sig.get("pattern", ""))
        existing_keys.add(key)

    upstream_keys = set()
    for sig in all_sigs:
        key = (sig["name"], sig["header"], sig.get("pattern", ""))
        upstream_keys.add(key)

    custom_kept = 0
    for sig in existing:
        key = (sig["name"], sig["header"], sig.get("pattern", ""))
        if key not in upstream_keys:
            all_sigs.append(sig)
            custom_kept += 1

    # Sort by category then name for readability
    all_sigs.sort(key=lambda s: (s["category"], s["name"], s["header"]))

    # Write output
    with open(output_path, "w") as f:
        json.dump(all_sigs, f, indent=2)

    print(f"\nWrote {len(all_sigs)} signatures to {output_path}")
    print(f"  From upstream: {len(all_sigs) - custom_kept}")
    print(f"  Custom kept: {custom_kept}")
    print(f"\nRebuild psnet: cargo build")

if __name__ == "__main__":
    main()
