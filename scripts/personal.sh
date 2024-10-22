#!/usr/bin/env bash

set -euo pipefail

# Configuration
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
trap 'rm -rf "$TEMP_DIR"' EXIT

# Function to log messages
log() {
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    printf "[%s] %s\n" "$timestamp" "$1" | tee -a "${PATHS[LOG_FILE]}"
}

# Function to check dependencies
check_dependencies() {
    local -r deps=("jq" "parallel")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log "Error: $dep is not installed. Please install it to run this script."
            exit 1
        fi
    done
}

# Function to process a chunk of the file
process_chunk() {
    jq -r 'select(.status == "REQUEST_BLOCKED" and .device == "Phone") | .domain'
}

# Function to generate blocklist
generate_blocklist() {
    local -r format="$1"
    local -r output_file="$2"
    local -r domain_count="$3"
    local -r timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")

    log "Generating $format format blocklist..."

    {
        if [[ "$format" == "hosts" ]]; then
            echo "# Title: Personal Blocklist (Hosts Format)"
            echo "# Description: Domains blocked based on personal preferences"
            echo "# Last updated: $timestamp"
            echo "# Number of unique domains: $domain_count"
            echo "#"
            echo "# Hosts file format: 0.0.0.0 example.com"
            echo
            sed 's/^/0.0.0.0 /'
        else
            echo "! Title: Personal Blocklist (AdGuard Format)"
            echo "! Description: Domains blocked based on personal preferences"
            echo "! Last updated: $timestamp"
            echo "! Number of unique domains: $domain_count"
            echo "! Compatible with AdGuard"
            echo "!"
            echo "! Blocklist format: ||example.com^"
            echo
            sed 's/^/||/' | sed 's/$/^/'
        fi
    } > "$output_file"

    log "$format format blocklist written to $output_file"
}

# Function to generate detailed statistics and append to log file
generate_stats() {
    local -r domains_file="$1"
    log "Generating detailed statistics..."

    {
        echo
        echo "Blocklist Statistics"
        echo "===================="
        echo "Total unique domains: $(wc -l < "$domains_file")"
        echo
        echo "Top 10 TLDs:"
        cut -d. -f2- "$domains_file" | awk -F. '{print $NF}' | LC_ALL=C sort | uniq -c | sort -rn | head -n 10
        echo
        echo "Top 20 Domains:"
        LC_ALL=C sort "$domains_file" | uniq -c | sort -rn | head -n 20
    } >> "${PATHS[LOG_FILE]}"

    log "Detailed statistics appended to log file"
}

# Main execution
main() {
    # Ensure logs directory exists
    mkdir -p "${PATHS[LOGS_DIR]}"
    # Clear previous log file
    : > "${PATHS[LOG_FILE]}"

    check_dependencies

    if [[ ! -f "${PATHS[INPUT_FILE]}" ]]; then
        log "Error: Input file ${PATHS[INPUT_FILE]} not found!"
        exit 1
    fi

    mkdir -p "${PATHS[OUTPUT_DIR]}"

    log "Starting blocklist generation..."

    log "Processing input file and extracting unique domains..."
    export -f process_chunk
    < "${PATHS[INPUT_FILE]}" parallel --pipe -N1000 --block 1M process_chunk | \
        LC_ALL=C sort -u > "$TEMP_DIR/domains.txt"

    # If the previous blocklist exists, append its domains to the new list
    if [[ -f "${PATHS[OUTPUT_FILE_HOSTS]}" ]]; then
        log "Appending previous blocklist entries to new blocklist..."
        grep -v '^#' "${PATHS[OUTPUT_FILE_HOSTS]}" | awk '{print $2}' >> "$TEMP_DIR/domains.txt"
    fi

    # Remove duplicates from the combined list of previous and new domains
    log "Removing duplicates from combined domains..."
    LC_ALL=C sort -u "$TEMP_DIR/domains.txt" > "$TEMP_DIR/combined_domains.txt"

    local -r domain_count=$(wc -l < "$TEMP_DIR/combined_domains.txt")
    log "Unique domains extracted: $domain_count"

    # Generate blocklists in parallel
    generate_blocklist "hosts" "${PATHS[OUTPUT_FILE_HOSTS]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" &
    generate_blocklist "adguard" "${PATHS[OUTPUT_FILE_ADGUARD]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" &
    wait

    generate_stats "$TEMP_DIR/combined_domains.txt"

    log "Blocklist generation process finished successfully."
}

main "$@"