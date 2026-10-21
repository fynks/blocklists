#!/usr/bin/env bash
#
# url-to-hosts.sh - Extract domains from blocked.json and build a hosts blocklist
# Usage: ./url-to-hosts.sh [options]
#
# Options:
#   -j FILE   Path to blocked.json (default: ./blocked.json)
#   -k BASE   Additional base domain whose subdomains are skipped
#   -s        Show per-section deduplication statistics
#   -v        Verbose mode (show duplicates being removed)
#   -h        Show this help
#
# Pipeline:
#   blocked.json -> unique domains -> url-list.txt (new "Blocked JSON" section)
#                -> global deduplication -> blocklists/personal.txt (hosts format)
#
# Subdomains of the base domains listed in SKIP_SUBDOMAIN_BASES are dropped
# from every step (see the setting near the top of this script).
#
# Everything is done with streaming tools (jq + awk + sort) so the whole
# pipeline stays linear in the size of the input.

set -euo pipefail  # Exit on error, undefined variables, and pipe failures
IFS=$'\n\t'        # Set safer Internal Field Separator

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Default values for options (can be overridden via command line flags)
SHOW_STATS=false
VERBOSE=false
JSON_FILE=""
EXTRA_SKIP_BASES=()

# ---------------------------------------------------------------------------
# Skip list: any *subdomain* of the base domains below is dropped from every
# step (extraction, url-list.txt, deduplication and the generated blocklist).
# The base domain itself is kept.
#
# Example: "*.metric.gstatic.com" and "*.fbcdn.net" are used with randomly
# generated subdomains, so they would otherwise add thousands of useless
# entries to the list.
# ---------------------------------------------------------------------------
readonly SKIP_SUBDOMAIN_BASES=(
    "metric.gstatic.com"
    "fbcdn.net"
)

# Script directory and file paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INPUT_FILE="${SCRIPT_DIR}/url-list.txt"
readonly OUTPUT_FILE="${SCRIPT_DIR}/../blocklists/personal.txt"
readonly DEFAULT_JSON_FILE="${SCRIPT_DIR}/blocked.json"
readonly SECTION_MARKER="#============ Blocked JSON ============"

# Temporary files
TEMP_JSON_DOMAINS=""
TEMP_MERGED=""
TEMP_CLEAN=""
TEMP_SORTED=""
TEMP_SKIP_LIST=""

# Cleanup temporary files on exit
cleanup() {
    rm -f "${TEMP_JSON_DOMAINS}" "${TEMP_MERGED}" "${TEMP_CLEAN}" "${TEMP_SORTED}" "${TEMP_SKIP_LIST}"
}
trap cleanup EXIT

# Print colored message
print_status() {
    local color=$1
    shift
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*"
}

# Validate input files exist
validate_input() {
    if [[ ! -f "${JSON_FILE}" ]]; then
        print_status "${RED}" "Error: blocked.json not found: ${JSON_FILE}"
        exit 1
    fi

    if [[ ! -s "${JSON_FILE}" ]]; then
        print_status "${RED}" "Error: blocked.json is empty: ${JSON_FILE}"
        exit 1
    fi

    if [[ ! -f "${INPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Input file not found: ${INPUT_FILE}"
        exit 1
    fi

    if [[ ! -s "${INPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Input file is empty: ${INPUT_FILE}"
        exit 1
    fi
}

# Write the configured skip bases to a file (read by the awk passes)
write_skip_list() {
    TEMP_SKIP_LIST="$(mktemp)"

    local base
    for base in "${SKIP_SUBDOMAIN_BASES[@]}" "${EXTRA_SKIP_BASES[@]}"; do
        [[ -z "${base}" ]] && continue
        printf '%s\n' "${base,,}" >> "${TEMP_SKIP_LIST}"
    done

    if [ "${VERBOSE}" = true ]; then
        print_status "${YELLOW}" "Skipping subdomains of:"
        while IFS= read -r base; do
            echo "  *.${base}" >&2
        done < "${TEMP_SKIP_LIST}"
    fi
}

# Extract domains from blocked.json -> TEMP_JSON_DOMAINS (unique, valid)
extract_json_domains() {
    print_status "${YELLOW}" "Extracting domains from ${JSON_FILE}..."

    local raw_domains
    raw_domains="$(mktemp)"

    if command -v jq >/dev/null 2>&1; then
        # Streaming extraction of the "domain" field of every item
        jq -r '.items[]? | .domain // empty' "${JSON_FILE}" > "${raw_domains}"
    else
        # Fallback parser when jq is not available
        grep -oE '"domain"[[:space:]]*:[[:space:]]*"[^"]+"' "${JSON_FILE}" \
            | sed -E 's/.*"domain"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
            > "${raw_domains}"
    fi

    local total
    total="$(wc -l < "${raw_domains}")"

    # Validate, drop skipped subdomains and deduplicate in one streaming pass
    awk -v skipfile="${TEMP_SKIP_LIST}" '
        function load_skip() {
            while ((getline line < skipfile) > 0) {
                line = tolower(line)
                gsub(/^[ \t]+|[ \t]+$/, "", line)
                if (line != "" && line !~ /^#/) {
                    nskip++
                    skip[nskip] = line
                }
            }
            close(skipfile)
        }

        # Returns 1 when the domain is a strict subdomain of a skipped base
        function is_skipped(domain,   i, base) {
            domain = tolower(domain)
            for (i = 1; i <= nskip; i++) {
                base = skip[i]
                if (length(domain) > length(base) + 1 && \
                    substr(domain, length(domain) - length(base)) == "." base)
                    return 1
            }
            return 0
        }

        BEGIN { load_skip() }

        !/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/ { next }
        is_skipped($0) { skipped++; next }
        {
            key = tolower($0)
            if (!(key in seen)) {
                seen[key] = 1
                print
            }
        }

        END { if (skipped > 0) print skipped > "/dev/stderr" }
    ' "${raw_domains}" > "${TEMP_JSON_DOMAINS}" 2> "${TEMP_JSON_DOMAINS}.skipped"
    local skipped
    skipped="$(head -n 1 "${TEMP_JSON_DOMAINS}.skipped" 2>/dev/null || true)"
    skipped="${skipped:-0}"
    rm -f "${raw_domains}" "${TEMP_JSON_DOMAINS}.skipped"

    local unique
    unique="$(wc -l < "${TEMP_JSON_DOMAINS}")"
    print_status "${GREEN}" "Extracted ${total} entries, ${unique} unique valid domains, $(( total - unique - skipped )) duplicates and ${skipped} skipped subdomains dropped"
}

# Merge the JSON domains into url-list.txt as a dedicated section
merge_into_url_list() {
    print_status "${YELLOW}" "Merging domains into ${INPUT_FILE}..."

    # Drop a previously generated "Blocked JSON" section (marker -> next section)
    awk -v marker="${SECTION_MARKER}" '
        $0 == marker { skip = 1; next }
        skip && /^#=+[[:space:]]/ { skip = 0 }
        skip { next }
        { print }
    ' "${INPUT_FILE}" > "${TEMP_MERGED}"

    # Append the fresh section
    {
        printf '%s\n' "${SECTION_MARKER}"
        cat "${TEMP_JSON_DOMAINS}"
    } >> "${TEMP_MERGED}"

    chmod --reference="${INPUT_FILE}" "${TEMP_MERGED}" 2>/dev/null || true
    mv "${TEMP_MERGED}" "${INPUT_FILE}"

    print_status "${GREEN}" "Updated source list: ${INPUT_FILE}"
}

# Deduplicate the whole list (globally) while keeping the section structure
deduplicate_list() {
    print_status "${YELLOW}" "Deduplicating ${INPUT_FILE}..."

    local dup_file
    dup_file="$(mktemp)"

    local skip_file
    skip_file="$(mktemp)"

    # Single pass, associative array based dedup (O(n) instead of O(n^2) greps)
    awk -v stats="$([[ ${SHOW_STATS} == true ]] && echo 1 || echo 0)" \
        -v dupfile="${dup_file}" \
        -v skipfile="${TEMP_SKIP_LIST}" \
        -v skipfile_out="${skip_file}" '
        function load_skip() {
            while ((getline line < skipfile) > 0) {
                line = tolower(line)
                gsub(/^[ \t]+|[ \t]+$/, "", line)
                if (line != "" && line !~ /^#/) {
                    nskip++
                    skip[nskip] = line
                }
            }
            close(skipfile)
        }

        # Returns 1 when the domain is a strict subdomain of a skipped base
        function is_skipped(domain,   i, base) {
            domain = tolower(domain)
            for (i = 1; i <= nskip; i++) {
                base = skip[i]
                if (length(domain) > length(base) + 1 && \
                    substr(domain, length(domain) - length(base)) == "." base)
                    return 1
            }
            return 0
        }

        BEGIN {
            section = "(top)"
            section_original = 0
            section_unique = 0
            load_skip()
        }

        # Section headers are kept as-is
        /^#=+[[:space:]]/ {
            if (stats) {
                printf("  Section: %s\n    Original: %d, Unique: %d, Removed: %d\n",
                       section, section_original, section_unique,
                       section_original - section_unique) > "/dev/stderr"
            }
            line = $0
            sub(/^#=+[[:space:]]*/, "", line)
            sub(/[[:space:]]*=*$/, "", line)
            section = line
            section_original = 0
            section_unique = 0
            print $0
            next
        }

        # Any other comment line is dropped
        /^[[:space:]]*#/ { next }

        {
            line = $0
            gsub(/^[[:space:]]+/, "", line)
            gsub(/[[:space:]]+$/, "", line)
            if (line == "") next

            section_original++

            # Skipped subdomains are dropped from the list as well
            if (is_skipped(line)) {
                print line > skipfile_out
                next
            }

            # DNS is case insensitive: dedupe on the lowercased key but keep
            # the original spelling of the first occurrence
            key = tolower(line)

            if (key in seen) {
                print line > dupfile
                next
            }

            seen[key] = 1
            section_unique++
            print line
        }

        END {
            if (stats) {
                printf("  Section: %s\n    Original: %d, Unique: %d, Removed: %d\n",
                       section, section_original, section_unique,
                       section_original - section_unique) > "/dev/stderr"
            }
            close(dupfile)
            close(skipfile_out)
        }
    ' "${INPUT_FILE}" > "${TEMP_CLEAN}"

    if [ "${VERBOSE}" = true ] && [ -s "${dup_file}" ]; then
        while IFS= read -r dup; do
            echo "  Removing duplicate domain: ${dup}" >&2
        done < "${dup_file}"
    fi

    if [ "${VERBOSE}" = true ] && [ -s "${skip_file}" ]; then
        while IFS= read -r skipped_domain; do
            echo "  Skipping subdomain: ${skipped_domain}" >&2
        done < "${skip_file}"
    fi

    local removed skipped_removed
    removed="$(wc -l < "${dup_file}")"
    skipped_removed="$(wc -l < "${skip_file}")"
    rm -f "${dup_file}" "${skip_file}"

    chmod --reference="${INPUT_FILE}" "${TEMP_CLEAN}" 2>/dev/null || true
    mv "${TEMP_CLEAN}" "${INPUT_FILE}"

    local unique_count
    unique_count="$(grep -cve '^[[:space:]]*#' "${INPUT_FILE}" || true)"

    print_status "${GREEN}" "Deduplicated list: ${unique_count} unique domains, ${removed} duplicates removed, ${skipped_removed} skipped subdomains dropped"
}

# Generate hosts file
generate_hosts_file() {
    local output_dir
    output_dir="$(dirname "${OUTPUT_FILE}")"

    mkdir -p "${output_dir}"

    print_status "${YELLOW}" "Generating hosts file..."

    # Sorted unique domains (comments and blank lines removed)
    grep -vE '^[[:space:]]*(#|$)' "${INPUT_FILE}" | sort -u > "${TEMP_SORTED}"

    local unique_count
    unique_count="$(wc -l < "${TEMP_SORTED}")"

    local current_date
    current_date="$(date '+%d-%m-%Y')"

    {
        echo "# Title: Personal Blocklist (Hosts Format)"
        echo "# Description: Domains blocked based on personal preferences"
        echo "# Total unique domains: ${unique_count}"
        echo "# Generated at: ${current_date}"
        echo "#"
        echo "# Hosts file format: 0.0.0.0 example.com"
        echo ""
        sed 's/^/0.0.0.0 /' "${TEMP_SORTED}"
    } > "${OUTPUT_FILE}"

    print_status "${GREEN}" "Generated hosts file with ${unique_count} unique domains"
    print_status "${GREEN}" "Output: ${OUTPUT_FILE}"
}

# Validate output file
validate_output() {
    if [[ ! -f "${OUTPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Failed to generate output file"
        exit 1
    fi

    if ! grep -q '^0\.0\.0\.0 ' "${OUTPUT_FILE}"; then
        print_status "${RED}" "Error: Output file does not contain valid hosts entries"
        exit 1
    fi

    print_status "${GREEN}" "Validation successful!"
}

# Main execution
main() {
    while getopts "j:k:svh" opt; do
        case $opt in
            j) JSON_FILE="$OPTARG" ;;
            k) EXTRA_SKIP_BASES+=("$OPTARG") ;;
            s) SHOW_STATS=true ;;
            v) VERBOSE=true ;;
            h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Extracts domains from blocked.json, adds them to url-list.txt,"
                echo "deduplicates the list and generates a hosts format blocklist."
                echo ""
                echo "Options:"
                echo "  -j FILE   Path to blocked.json (default: ${DEFAULT_JSON_FILE})"
                echo "  -k BASE   Additional base domain whose subdomains are skipped"
                echo "  -s         Show per-section deduplication statistics"
                echo "  -v         Verbose mode (show duplicates being removed)"
                echo "  -h         Show this help"
                echo ""
                echo "Configured skip bases (subdomains of these are dropped):"
                for base in "${SKIP_SUBDOMAIN_BASES[@]}"; do
                    echo "  *.${base}"
                done
                exit 0
                ;;
            \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
        esac
    done

    JSON_FILE="${JSON_FILE:-${DEFAULT_JSON_FILE}}"

    TEMP_JSON_DOMAINS="$(mktemp)"
    TEMP_MERGED="$(mktemp)"
    TEMP_CLEAN="$(mktemp)"
    TEMP_SORTED="$(mktemp)"

    print_status "${GREEN}" "Starting blocklist generation from blocked.json..."

    write_skip_list
    validate_input
    extract_json_domains
    merge_into_url_list
    deduplicate_list
    generate_hosts_file
    validate_output

    print_status "${GREEN}" "Done! Blocklist is ready to deploy."
}

# Run main function
main "$@"
