#!/usr/bin/env bash
#
# url-to-hosts.sh - Merge blocked.json domains into url-list.txt and build
#                   a hosts format blocklist
#
# Usage: ./url-to-hosts.sh [options]
#
# Options:
#   -j FILE   Path to blocked.json (default: ./blocked.json)
#   -k BASE   Additional base domain whose subdomains are skipped
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

set -euo pipefail
IFS=$'\n\t'

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

SHOW_STATS=false
VERBOSE=false
JSON_FILE=""
EXTRA_SKIP_BASES=()

# Any *subdomain* of these bases is dropped everywhere; the base itself is
# kept. Both are hosts that publish random machine-generated subdomains that
# would otherwise add thousands of entries.
readonly SKIP_SUBDOMAIN_BASES=(
    "metric.gstatic.com"
    "fbcdn.net"
)

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INPUT_FILE="${SCRIPT_DIR}/url-list.txt"
readonly OUTPUT_FILE="${SCRIPT_DIR}/../blocklists/personal.txt"
readonly DEFAULT_JSON_FILE="${SCRIPT_DIR}/blocked.json"
readonly SECTION_MARKER="#============ Blocked JSON ============"

TEMP_JSON_DOMAINS=""
TEMP_OLD_SECTION=""
TEMP_MERGED=""
TEMP_CLEAN=""
TEMP_SORTED=""
TEMP_SKIP_LIST=""

cleanup() {
    rm -f "${TEMP_JSON_DOMAINS}" "${TEMP_JSON_DOMAINS}.union" \
          "${TEMP_OLD_SECTION}" "${TEMP_MERGED}" "${TEMP_CLEAN}" \
          "${TEMP_SORTED}" "${TEMP_SKIP_LIST}"
}
trap cleanup EXIT

print_status() {
    local color=$1
    shift
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*"
}

# Validate input files. blocked.json is optional; url-list.txt is only
# required when the JSON cannot supply domains either.
validate_input() {
    if [[ -f "${JSON_FILE}" && -s "${JSON_FILE}" ]]; then
        HAVE_JSON=true
    else
        HAVE_JSON=false
        if [[ ! -e "${JSON_FILE}" ]]; then
            print_status "${YELLOW}" "blocked.json not found (${JSON_FILE}), continuing with url-list.txt only"
        else
            print_status "${YELLOW}" "blocked.json is empty (${JSON_FILE}), continuing with url-list.txt only"
        fi
    fi

    if [[ ! -f "${INPUT_FILE}" || ! -s "${INPUT_FILE}" ]]; then
        if [[ "${HAVE_JSON}" == true ]]; then
            print_status "${YELLOW}" "url-list.txt missing or empty, a new list will be created at ${INPUT_FILE}"
        else
            print_status "${RED}" "Error: no input available: ${JSON_FILE} is absent/empty and ${INPUT_FILE} is missing or empty"
            exit 1
        fi
    fi
}

# Dump the skip bases to a temp file the awk passes read
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

# Extract domains from blocked.json into TEMP_JSON_DOMAINS (unique, valid).
# On failure TEMP_JSON_DOMAINS is left empty and the caller falls back to
# url-list.txt.
extract_json_domains() {
    if [[ "${HAVE_JSON}" != true ]]; then
        : > "${TEMP_JSON_DOMAINS}"
        return 0
    fi

    print_status "${YELLOW}" "Extracting domains from ${JSON_FILE}..."

    local raw_domains jq_failed=false
    raw_domains="$(mktemp)"

    if command -v jq >/dev/null 2>&1; then
        if ! jq -r '.items[]? | .domain // empty' "${JSON_FILE}" > "${raw_domains}" 2>/dev/null; then
            jq_failed=true
        fi
    else
        grep -oE '"domain"[[:space:]]*:[[:space:]]*"[^"]+"' "${JSON_FILE}" \
            | sed -E 's/.*"domain"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
            > "${raw_domains}" || true
    fi

    if [[ "${jq_failed}" == true ]]; then
        print_status "${YELLOW}" "Warning: could not parse ${JSON_FILE}, continuing with url-list.txt only"
        : > "${TEMP_JSON_DOMAINS}"
        rm -f "${raw_domains}"
        return 0
    fi

    local total
    total="$(wc -l < "${raw_domains}")"

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

    if [[ ! -s "${TEMP_JSON_DOMAINS}" ]]; then
        print_status "${YELLOW}" "No valid domains found in ${JSON_FILE}, continuing with url-list.txt only"
        return 0
    fi

    local unique
    unique="$(wc -l < "${TEMP_JSON_DOMAINS}")"
    print_status "${GREEN}" "Extracted ${total} entries, ${unique} unique valid domains, $(( total - unique - skipped )) duplicates and ${skipped} skipped subdomains dropped"
}

# Union the fresh extraction with the previous "Blocked JSON" section so
# domains survive re-runs even after leaving the JSON.
merge_into_url_list() {
    # Nothing new to add, leave url-list.txt alone
    if [[ ! -s "${TEMP_JSON_DOMAINS}" ]]; then
        return 0
    fi

    print_status "${YELLOW}" "Merging domains into ${INPUT_FILE}..."

    : > "${TEMP_OLD_SECTION}"
    if [[ -f "${INPUT_FILE}" && -s "${INPUT_FILE}" ]]; then
        awk -v marker="${SECTION_MARKER}" '
            $0 == marker          { grab = 1; next }
            grab && /^#=+[[:space:]]/ { grab = 0 }
            grab && /^[[:space:]]*#/  { next }
            grab && NF               { print }
        ' "${INPUT_FILE}" > "${TEMP_OLD_SECTION}"

        if [[ -s "${TEMP_OLD_SECTION}" ]]; then
            local kept
            kept="$(wc -l < "${TEMP_OLD_SECTION}")"
            print_status "${YELLOW}" "Keeping ${kept} domains already present in the Blocked JSON section"
        fi
    fi

    # Case-insensitive dedup happens in the next pass, so sort -u is enough here
    if [[ -s "${TEMP_OLD_SECTION}" ]]; then
        sort -u "${TEMP_OLD_SECTION}" "${TEMP_JSON_DOMAINS}" > "${TEMP_JSON_DOMAINS}.union"
    else
        cp "${TEMP_JSON_DOMAINS}" "${TEMP_JSON_DOMAINS}.union"
    fi

    if [[ -f "${INPUT_FILE}" && -s "${INPUT_FILE}" ]]; then
        awk -v marker="${SECTION_MARKER}" '
            $0 == marker { skip = 1; next }
            skip && /^#=+[[:space:]]/ { skip = 0 }
            skip { next }
            { print }
        ' "${INPUT_FILE}" > "${TEMP_MERGED}"
    else
        : > "${TEMP_MERGED}"
    fi

    {
        printf '%s\n' "${SECTION_MARKER}"
        cat "${TEMP_JSON_DOMAINS}.union"
    } >> "${TEMP_MERGED}"

    chmod --reference="${INPUT_FILE}" "${TEMP_MERGED}" 2>/dev/null || true
    mv "${TEMP_MERGED}" "${INPUT_FILE}"

    local total_domain_count
    total_domain_count="$(wc -l < "${TEMP_JSON_DOMAINS}.union")"
    print_status "${GREEN}" "Updated source list with ${total_domain_count} domains in the Blocked JSON section: ${INPUT_FILE}"
}

# Normalize URLs (https://x.com/p?y:8080 -> x.com), drop skipped subdomains
# and invalid entries, deduplicate globally and case-insensitively.
deduplicate_list() {
    if [[ ! -f "${INPUT_FILE}" || ! -s "${INPUT_FILE}" ]]; then
        return 0
    fi

    print_status "${YELLOW}" "Deduplicating ${INPUT_FILE}..."

    local dup_file skip_file invalid_file
    dup_file="$(mktemp)"
    skip_file="$(mktemp)"
    invalid_file="$(mktemp)"

    # Single-pass O(n) dedup via awk associative arrays
    awk -v stats="$([[ ${SHOW_STATS} == true ]] && echo 1 || echo 0)" \
        -v verbose="$([[ ${VERBOSE} == true ]] && echo 1 || echo 0)" \
        -v dupfile="${dup_file}" \
        -v invalidfile="${invalid_file}" \
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

        /^[[:space:]]*#/ { next }

        {
            line = $0
            gsub(/^[[:space:]]+/, "", line)
            gsub(/[[:space:]]+$/, "", line)
            if (line == "") next

            # Markdown-style separators (---) would leak into the blocklist
            if (line ~ /^-+$/) next

            section_original++

            # Normalize URLs to bare domains:
            #   https://sub.host.tld/path?a=b#anchor:8080 -> sub.host.tld
            if (line ~ /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//) urls++
            sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", line)  # scheme
            sub(/[\/?#:].*/, "", line)                     # path/query/fragment/port
            sub(/\.+$/, "", line)                          # trailing dot

            if (line == "") next

            if (line !~ /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/) {
                invalid++
                if (verbose) print "  Dropping invalid domain: " line > "/dev/stderr"
                print line > invalidfile
                next
            }

            # Skipped subdomains are dropped from the list as well
            if (is_skipped(line)) {
                print line > skipfile_out
                next
            }

            # DNS is case insensitive: dedupe on the lowercased key, keep the
            # original spelling of the first occurrence
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
            close(invalidfile)
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

    local removed skipped_removed invalid_removed
    removed="$(wc -l < "${dup_file}")"
    skipped_removed="$(wc -l < "${skip_file}")"
    invalid_removed="$(wc -l < "${invalid_file}")"
    rm -f "${dup_file}" "${skip_file}" "${invalid_file}"

    chmod --reference="${INPUT_FILE}" "${TEMP_CLEAN}" 2>/dev/null || true
    mv "${TEMP_CLEAN}" "${INPUT_FILE}"
    print_status "${GREEN}" "Updated source list with normalized, unique domains: ${INPUT_FILE}"

    local unique_count
    unique_count="$(grep -cve '^[[:space:]]*#' "${INPUT_FILE}" || true)"

    if [[ "${unique_count}" -eq 0 ]]; then
        print_status "${RED}" "Error: no valid domains found to generate a blocklist"
        exit 1
    fi

    print_status "${GREEN}" "Deduplicated list: ${unique_count} unique domains, ${removed} duplicates removed, ${skipped_removed} skipped subdomains dropped, ${invalid_removed} invalid entries dropped"
}

generate_hosts_file() {
    local output_dir
    output_dir="$(dirname "${OUTPUT_FILE}")"

    mkdir -p "${output_dir}"

    print_status "${YELLOW}" "Generating hosts file..."

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
                echo "Merges domains from blocked.json (optional) into url-list.txt,"
                echo "deduplicates the list and generates a hosts format blocklist."
                echo "Existing domains in url-list.txt are always kept."
                echo ""
                echo "Options:"
                echo "  -j FILE   Path to blocked.json (default: ${DEFAULT_JSON_FILE})"
                echo "  -k BASE   Additional base domain whose subdomains are skipped"
                echo "  -s        Show per-section deduplication statistics"
                echo "  -v        Verbose mode (show duplicates being removed)"
                echo "  -h        Show this help"
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
    TEMP_OLD_SECTION="$(mktemp)"
    TEMP_MERGED="$(mktemp)"
    TEMP_CLEAN="$(mktemp)"
    TEMP_SORTED="$(mktemp)"

    print_status "${GREEN}" "Starting blocklist generation..."

    write_skip_list
    validate_input
    extract_json_domains
    merge_into_url_list
    deduplicate_list
    generate_hosts_file
    validate_output

    print_status "${GREEN}" "Done! Blocklist is ready to deploy."
}

main "$@"
