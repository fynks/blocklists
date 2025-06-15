#!/usr/bin/env bash

set -euo pipefail

declare -A PATHS
PATHS=(
    [INPUT_FILE]="input.json"
    [OUTPUT_DIR]="../blocklists"
    [LOGS_DIR]="../.logs"
)
PATHS[OUTPUT_FILE_HOSTS]="${PATHS[OUTPUT_DIR]}/personal_blocklist_hosts.txt"
PATHS[OUTPUT_FILE_ADGUARD]="${PATHS[OUTPUT_DIR]}/personal_blocklist_adguard.txt"
PATHS[LOG_FILE]="${PATHS[LOGS_DIR]}/personal_blocklist_generation.log"

readonly TEMP_DIR=$(mktemp -d)
readonly SCRIPT_START_TIME=$(date +%s)
trap 'rm -rf "$TEMP_DIR"' EXIT

log() {
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    printf "[%s] %s\n" "$timestamp" "$1" | tee -a "${PATHS[LOG_FILE]}"
}

check_dependencies() {
    local -r deps=("jq" "parallel")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "Error: Missing dependencies: ${missing_deps[*]}. Please install them to run this script."
        exit 1
    fi
}

process_chunk() {
    jq -r 'select(.status == "REQUEST_BLOCKED" and .device == "Phone") | .domain // empty' | \
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' || true
}

generate_blocklist() {
    local -r format="$1"
    local -r output_file="$2"
    local -r domain_count="$3"
    local -r timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")

    log "Generating $format format blocklist with $domain_count domains..."

    {
        if [[ "$format" == "hosts" ]]; then
            cat << EOF
# Title: Personal Blocklist (Hosts Format)
# Description: Domains blocked based on personal preferences
# Last updated: $timestamp
# Number of unique domains: $domain_count
# Homepage: https://github.com/fynks/blocklists
#
# Hosts file format: 0.0.0.0 example.com

EOF
            awk '{print "0.0.0.0 " $0}'
        else
            cat << EOF
! Title: Personal Blocklist (AdGuard Format)
! Description: Domains blocked based on personal preferences
! Last updated: $timestamp
! Number of unique domains: $domain_count
! Homepage: https://github.com/fynks/blocklists
! Compatible with AdGuard, uBlock Origin, Pi-hole
!
! Blocklist format: ||example.com^

EOF
            awk '{print "||" $0 "^"}'
        fi
    } > "$output_file"

    log "$format format blocklist written to $output_file ($domain_count domains)"
}

generate_stats() {
    local -r domains_file="$1"
    local -r elapsed_time=$(($(date +%s) - SCRIPT_START_TIME))
    
    log "Generating detailed statistics..."

    {
        echo
        echo "Blocklist Generation Report"
        echo "=========================="
        echo "Generated on: $(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")"
        echo "Processing time: ${elapsed_time}s"
        echo "Total unique domains: $(wc -l < "$domains_file")"
        echo
        echo "Top 10 TLDs:"
        awk -F. '{print $NF}' "$domains_file" | LC_ALL=C sort | uniq -c | sort -rn | head -n 10 | awk '{printf "  %-6s %s\n", $1, $2}'
        echo
        echo "Top 20 Second-Level Domains:"
        awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print $0}' "$domains_file" | LC_ALL=C sort | uniq -c | sort -rn | head -n 20 | awk '{printf "  %-6s %s\n", $1, $2}'
        echo
        echo "Domain Length Distribution:"
        awk '{print length($0)}' "$domains_file" | LC_ALL=C sort -n | uniq -c | awk '{printf "  %2d chars: %d domains\n", $2, $1}' | tail -n 10
    } >> "${PATHS[LOG_FILE]}"

    log "Detailed statistics appended to log file (processing took ${elapsed_time}s)"
}

main() {
    # Create directories and initialize log
    mkdir -p "${PATHS[LOGS_DIR]}" "${PATHS[OUTPUT_DIR]}"
    : > "${PATHS[LOG_FILE]}"

    log "Starting personal blocklist generation..."

    check_dependencies

    # Validate input file
    if [[ ! -f "${PATHS[INPUT_FILE]}" ]]; then
        log "Error: Input file ${PATHS[INPUT_FILE]} not found!"
        exit 1
    elif [[ ! -s "${PATHS[INPUT_FILE]}" ]]; then
        log "Error: Input file ${PATHS[INPUT_FILE]} is empty!"
        exit 1
    fi

    log "Processing $(wc -l < "${PATHS[INPUT_FILE]}") lines from input file..."

    # Process input file with better error handling
    export -f process_chunk
    if ! < "${PATHS[INPUT_FILE]}" parallel --pipe -N1000 --block 1M process_chunk > "$TEMP_DIR/new_domains.txt" 2>/dev/null; then
        log "Warning: Some parallel processing errors occurred, continuing..."
    fi

    # Remove empty lines and sort
    grep -v '^$' "$TEMP_DIR/new_domains.txt" | LC_ALL=C sort -u > "$TEMP_DIR/domains.txt"

    # Merge with existing blocklist if it exists
    if [[ -f "${PATHS[OUTPUT_FILE_HOSTS]}" && -s "${PATHS[OUTPUT_FILE_HOSTS]}" ]]; then
        log "Merging with existing blocklist entries..."
        grep -v '^#' "${PATHS[OUTPUT_FILE_HOSTS]}" | awk '$2 {print $2}' >> "$TEMP_DIR/domains.txt"
    fi

    # Final deduplication and sorting
    LC_ALL=C sort -u "$TEMP_DIR/domains.txt" > "$TEMP_DIR/combined_domains.txt"

    local -r domain_count=$(wc -l < "$TEMP_DIR/combined_domains.txt")
    
    if [[ $domain_count -eq 0 ]]; then
        log "Warning: No valid domains found to process!"
        exit 1
    fi

    log "Processing $domain_count unique domains..."

    # Generate both formats in parallel with input redirection
    generate_blocklist "hosts" "${PATHS[OUTPUT_FILE_HOSTS]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" &
    local hosts_pid=$!
    generate_blocklist "adguard" "${PATHS[OUTPUT_FILE_ADGUARD]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" &
    local adguard_pid=$!

    # Wait for both processes and check exit status
    if ! wait $hosts_pid || ! wait $adguard_pid; then
        log "Error: Failed to generate one or more blocklist formats"
        exit 1
    fi

    generate_stats "$TEMP_DIR/combined_domains.txt"

    log "Blocklist generation completed successfully!"
    log "Files generated:"
    log "  - Hosts format: ${PATHS[OUTPUT_FILE_HOSTS]}"
    log "  - AdGuard format: ${PATHS[OUTPUT_FILE_ADGUARD]}"
}

main "$@"