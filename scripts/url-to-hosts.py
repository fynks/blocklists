#!/usr/bin/env python3
#
# url-to-hosts.py - Merge blocked.json domains into url-list.txt and build
#                   a hosts format blocklist
#
# Usage: url-to-hosts.py [options]
#
# Options:
#   -j FILE   Path to blocked.json (default: ./blocked.json)
#   -k BASE   Additional base domain whose subdomains are skipped (repeatable)
#   -s        Show per-section deduplication statistics
#   -v        Verbose mode (show duplicates being removed)
#   -h        Show this help
#
# Pipeline: blocked.json (optional, unioned into the "Blocked JSON" section
# of url-list.txt) + url-list.txt -> URL normalization + global dedup ->
# blocklists/personal.txt (hosts format)
#
# blocked.json is optional: when it is absent, empty or unparsable the
# script works with url-list.txt only. Domains already in url-list.txt are
# always kept.

import argparse
import functools
import json
import locale
import os
import re
import stat
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JSON_FILE = os.path.join(SCRIPT_DIR, "blocked.json")
INPUT_FILE = os.path.join(SCRIPT_DIR, "url-list.txt")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "..", "blocklists", "personal.txt")

SECTION_MARKER = "#============ Blocked JSON ============"
SECTION_HEADER_RE = re.compile(r"^#=+\s")

# Any *subdomain* of these bases is dropped everywhere; the base itself is
# kept. Both are hosts that publish random machine-generated subdomains that
# would otherwise add thousands of entries.
SKIP_SUBDOMAIN_BASES = [
    "metric.gstatic.com",
    "fbcdn.net",
    "rekhtadictionary.com",
]

# Bare domain: labels of alnum/hyphen, no leading/trailing hyphen per label.
DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$"
)
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
URL_SPLIT_RE = re.compile(r"[/?#:].*")
DOMAIN_FIELD_RE = re.compile(r'"domain"\s*:\s*"([^"]+)"')

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def print_status(color, *args):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{color}[{now}]{NC} " + " ".join(str(a) for a in args))


def print_warn(*args):
    print_status(YELLOW, *args)


def print_error(*args):
    print_status(RED, *args)


def load_skip_bases(extra_bases, verbose):
    """Built-in plus user-supplied base domains, lowercased and cleaned."""
    bases = set()
    for base in list(SKIP_SUBDOMAIN_BASES) + list(extra_bases):
        base = base.strip().lower()
        if base and not base.startswith("#"):
            bases.add(base)
    if verbose and bases:
        print_status(YELLOW, "Skipping subdomains of:")
        for base in sorted(bases):
            print(f"  *.{base}", file=sys.stderr)
    return bases


def is_skipped(domain, skip_bases):
    """True if domain is a strict subdomain of any skip base."""
    domain = domain.lower()
    for base in skip_bases:
        if domain.endswith("." + base):
            return True
    return False


def replace_file(temp_path, dest_path):
    """Move temp_path over dest_path, preserving the destination's mode."""
    try:
        mode = stat.S_IMODE(os.stat(dest_path).st_mode)
        os.chmod(temp_path, mode)
    except OSError:
        pass
    os.replace(temp_path, dest_path)


def file_exists_nonempty(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


def gnu_sorted(iterable):
    """Sort like GNU sort: locale collation under the current environment."""
    locale.setlocale(locale.LC_ALL, "")
    return sorted(iterable, key=functools.cmp_to_key(locale.strcoll))


def validate_input(json_file, have_json):
    """blocked.json is optional; url-list.txt is only required when the
    JSON cannot supply domains either."""
    if not file_exists_nonempty(json_file):
        if not os.path.exists(json_file):
            print_warn(f"blocked.json not found ({json_file}), "
                       "continuing with url-list.txt only")
        else:
            print_warn(f"blocked.json is empty ({json_file}), "
                       "continuing with url-list.txt only")

    if not file_exists_nonempty(INPUT_FILE):
        if have_json:
            print_warn(f"url-list.txt missing or empty, "
                       f"a new list will be created at {INPUT_FILE}")
        else:
            print_error(f"Error: no input available: {json_file} is "
                        f"absent/empty and {INPUT_FILE} is missing or empty")
            sys.exit(1)


def extract_json_domains(json_file, skip_bases, verbose):
    """Extract unique, valid domains from blocked.json.

    Returns (domains, stats) where domains is a sorted list. On failure the
    list is empty and the caller falls back to url-list.txt only.
    """
    if not file_exists_nonempty(json_file):
        return [], None

    print_warn(f"Extracting domains from {json_file}...")

    try:
        with open(json_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        raw_domains = [item["domain"] for item in data.get("items", [])
                       if isinstance(item, dict)
                       and isinstance(item.get("domain"), str)]
    except (OSError, ValueError):
        print_warn(f"Warning: could not parse {json_file}, "
                   "continuing with url-list.txt only")
        return [], None

    total = len(raw_domains)
    ordered = {}
    skipped = 0
    for domain in raw_domains:
        domain = domain.strip()
        key = domain.lower()
        if not DOMAIN_RE.match(domain):
            continue
        if is_skipped(key, skip_bases):
            skipped += 1
            continue
        if key not in ordered:
            ordered[key] = domain

    domains = list(ordered.values())
    unique = len(domains)
    if unique == 0:
        print_warn(f"No valid domains found in {json_file}, "
                   "continuing with url-list.txt only")
        return [], None

    duplicates = total - unique - skipped
    print_status(GREEN,
                 f"Extracted {total} entries, {unique} unique valid domains, "
                 f"{duplicates} duplicates and {skipped} skipped subdomains "
                 "dropped")
    # First-seen order, like the awk pass: sort -u is only applied when the
    # fresh domains are unioned with a non-empty old section.
    return list(domains), {"total": total, "unique": unique,
                           "duplicates": duplicates, "skipped": skipped}


def read_blocked_json_section(path):
    """Domains from the previous "Blocked JSON" section of url-list.txt."""
    domains = []
    if not file_exists_nonempty(path):
        return domains
    grab = False
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line == SECTION_MARKER:
                grab = True
                continue
            if grab and SECTION_HEADER_RE.match(line):
                break
            if grab and line.lstrip().startswith("#"):
                continue
            if grab and line.strip():
                domains.append(line.strip())
    return domains


def merge_into_url_list(json_domains, verbose):
    """Union the fresh extraction with the previous "Blocked JSON" section
    so domains survive re-runs even after leaving the JSON."""
    if not json_domains:
        return

    print_warn(f"Merging domains into {INPUT_FILE}...")

    old_section = read_blocked_json_section(INPUT_FILE)
    if old_section:
        print_warn(f"Keeping {len(old_section)} domains already present "
                   "in the Blocked JSON section")

    # Case-insensitive dedup happens in the next pass, so a plain union of
    # both sets is enough here (sort -u); with nothing to union, the fresh
    # domains are kept in JSON order like the bash cp fallback.
    if old_section:
        union = gnu_sorted(set(old_section) | set(json_domains))
    else:
        union = json_domains

    # Rewrite url-list.txt without the old section, then append the union.
    lines = []
    if file_exists_nonempty(INPUT_FILE):
        skip = False
        with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line == SECTION_MARKER:
                    skip = True
                    continue
                if skip and SECTION_HEADER_RE.match(line):
                    skip = False
                if skip:
                    continue
                lines.append(line)

    tmp = INPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
        f.write(SECTION_MARKER + "\n")
        for domain in union:
            f.write(domain + "\n")

    replace_file(tmp, INPUT_FILE)
    print_status(GREEN, f"Updated source list with {len(union)} domains "
                        f"in the Blocked JSON section: {INPUT_FILE}")


def normalize_domain(line):
    """Normalize a URL to a bare domain:
    https://sub.host.tld/path?a=b#anchor:8080 -> sub.host.tld"""
    line = SCHEME_RE.sub("", line)
    line = URL_SPLIT_RE.sub("", line)      # path/query/fragment/port
    return line.rstrip(".")                # trailing dot


def deduplicate_list(skip_bases, show_stats, verbose):
    """Normalize URLs, drop skipped subdomains and invalid entries,
    deduplicate globally and case-insensitively."""
    if not file_exists_nonempty(INPUT_FILE):
        return

    print_warn(f"Deduplicating {INPUT_FILE}...")

    removed = 0
    skipped_removed = 0
    invalid_removed = 0
    cleaned = []
    seen = set()

    section = "(top)"
    section_original = 0
    section_unique = 0

    def flush_section_stats():
        if show_stats:
            print(f"  Section: {section}\n"
                  f"    Original: {section_original}, "
                  f"Unique: {section_unique}, "
                  f"Removed: {section_original - section_unique}",
                  file=sys.stderr)

    with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")

            # Section headers are kept verbatim; their title is extracted
            # for per-section statistics.
            if SECTION_HEADER_RE.match(line):
                flush_section_stats()
                section = line
                section = re.sub(r"^#=+\s*", "", section)
                section = re.sub(r"\s*=*$", "", section)
                section_original = 0
                section_unique = 0
                cleaned.append(line)
                continue

            if line.lstrip().startswith("#"):
                continue

            line = line.strip()
            if not line:
                continue

            # Markdown-style separators (---) would leak into the blocklist
            if re.match(r"^-+$", line):
                continue

            section_original += 1

            line = normalize_domain(line)
            if not line:
                continue

            if not DOMAIN_RE.match(line):
                invalid_removed += 1
                if verbose:
                    print(f"  Dropping invalid domain: {line}",
                          file=sys.stderr)
                continue

            # Skipped subdomains are dropped from the list as well
            if is_skipped(line, skip_bases):
                skipped_removed += 1
                if verbose:
                    print(f"  Skipping subdomain: {line}", file=sys.stderr)
                continue

            # DNS is case insensitive: dedupe on the lowercased key, keep
            # the original spelling of the first occurrence
            key = line.lower()
            if key in seen:
                removed += 1
                if verbose:
                    print(f"  Removing duplicate domain: {line}",
                          file=sys.stderr)
                continue

            seen.add(key)
            section_unique += 1
            cleaned.append(line)

    flush_section_stats()

    tmp = INPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for line in cleaned:
            f.write(line + "\n")
    replace_file(tmp, INPUT_FILE)
    print_status(GREEN, "Updated source list with normalized, "
                        f"unique domains: {INPUT_FILE}")

    unique_count = sum(
        1 for line in cleaned if line.strip() and not line.startswith("#")
    )

    if unique_count == 0:
        print_error("Error: no valid domains found to generate a blocklist")
        sys.exit(1)

    print_status(GREEN,
                 f"Deduplicated list: {unique_count} unique domains, "
                 f"{removed} duplicates removed, "
                 f"{skipped_removed} skipped subdomains dropped, "
                 f"{invalid_removed} invalid entries dropped")


def generate_hosts_file():
    output_dir = os.path.dirname(os.path.abspath(OUTPUT_FILE))
    os.makedirs(output_dir, exist_ok=True)

    print_warn("Generating hosts file...")

    # Collate like GNU sort under the current locale so the output ordering
    # matches the previous bash implementation.
    domains = gnu_sorted(
        line.strip() for line in read_non_comment_lines(INPUT_FILE)
    )
    unique_count = len(domains)
    current_date = datetime.now().strftime("%d-%m-%Y")

    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# Title: Personal Blocklist (Hosts Format)\n")
        f.write("# Description: Domains blocked based on personal "
                "preferences\n")
        f.write(f"# Total unique domains: {unique_count}\n")
        f.write(f"# Generated at: {current_date}\n")
        f.write("#\n")
        f.write("# Hosts file format: 0.0.0.0 example.com\n")
        f.write("\n")
        for domain in domains:
            f.write(f"0.0.0.0 {domain}\n")

    os.replace(tmp, OUTPUT_FILE)

    print_status(GREEN, f"Generated hosts file with {unique_count} "
                        "unique domains")
    print_status(GREEN, f"Output: {OUTPUT_FILE}")


def read_non_comment_lines(path):
    if not file_exists_nonempty(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped


def validate_output():
    if not os.path.isfile(OUTPUT_FILE):
        print_error("Error: Failed to generate output file")
        sys.exit(1)

    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("0.0.0.0 "):
                print_status(GREEN, "Validation successful!")
                return

    print_error("Error: Output file does not contain valid hosts entries")
    sys.exit(1)


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="url-to-hosts.py",
        description="Merges domains from blocked.json (optional) into "
                    "url-list.txt, deduplicates the list and generates a "
                    "hosts format blocklist. Existing domains in "
                    "url-list.txt are always kept.",
        epilog="Configured skip bases (subdomains of these are dropped):\n"
               + "\n".join(f"  *.{b}" for b in SKIP_SUBDOMAIN_BASES),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-j", "--json", metavar="FILE",
                        default=DEFAULT_JSON_FILE,
                        help=f"Path to blocked.json (default: "
                             f"{DEFAULT_JSON_FILE})")
    parser.add_argument("-k", "--skip-base", metavar="BASE",
                        action="append", default=[],
                        help="Additional base domain whose subdomains are "
                             "skipped (repeatable)")
    parser.add_argument("-s", "--stats", action="store_true",
                        help="Show per-section deduplication statistics")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose mode (show duplicates being removed)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    skip_bases = load_skip_bases(args.skip_base, args.verbose)
    json_file = args.json

    print_status(GREEN, "Starting blocklist generation...")

    # Whether the JSON can contribute domains decides how strict the
    # input validation needs to be.
    have_json = file_exists_nonempty(json_file)
    validate_input(json_file, have_json)

    json_domains, _stats = extract_json_domains(json_file, skip_bases,
                                                args.verbose)
    merge_into_url_list(json_domains, args.verbose)
    deduplicate_list(skip_bases, args.stats, args.verbose)
    generate_hosts_file()
    validate_output()

    print_status(GREEN, "Done! Blocklist is ready to deploy.")


if __name__ == "__main__":
    main()
