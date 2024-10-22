#!/usr/bin/env bash

set -euo pipefail

# Configuration
readonly INPUT_FILE="input.json"
readonly OUTPUT_DIR="../blocklists"
readonly LOGS_DIR="../.logs"
readonly OUTPUT_FILE_HOSTS="${OUTPUT_DIR}/personal_blocklist_hosts.txt"
readonly OUTPUT_FILE_ADGUARD="${OUTPUT_DIR}/personal_blocklist_adguard.txt"
readonly LOG_FILE="${LOGS_DIR}/personal_blocklist_generation.log"
readonly TEMP_DIR=$(mktemp -d)
readonly DOMAINS_FILE="${TEMP_DIR}/domains.txt"
readonly COMBINED_DOMAINS_FILE="${TEMP_DIR}/combined_domains.txt"

# Function to log messages
log() {
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    printf "[%s] %s\n" "$timestamp" "$1" | tee -a "$LOG_FILE"
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
    local -r domain_count=$(wc -l < "$DOMAINS_FILE")
    local -r timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")

    log "Generating $format format blocklist..."

    {
        if [[ "$format" == "hosts" ]]; then
            cat << EOF
# Title: Personal Blocklist (Hosts Format)
# Description: Domains blocked based on personal preferences
# Last updated: $timestamp
# Number of unique domains: $domain_count
#
# Hosts file format: 0.0.0.0 example.com

EOF
            # Format the hosts blocklist as hosts file (0.0.0.0 domain.com)
            sed 's/^/0.0.0.0 /' "$DOMAINS_FILE"
        else
            cat << EOF
! Title: Personal Blocklist (AdGuard Format)
! Description: Domains blocked based on personal preferences
! Last updated: $timestamp
! Number of unique domains: $domain_count
! Compatible with AdGuard
!
! Blocklist format: ||example.com^

EOF
            sed 's/^/||/' "$DOMAINS_FILE" | sed 's/$/^/'
        fi
    } > "$output_file"

    log "$format format blocklist written to $output_file"
}

# Function to generate detailed statistics and append to log file
generate_stats() {
    log "Generating detailed statistics..."

    {
        echo
        echo "Blocklist Statistics"
        echo "===================="
        echo "Total unique domains: $(wc -l < "$DOMAINS_FILE")"
        echo
        echo "Top 10 TLDs:"
        cut -d. -f2- "$DOMAINS_FILE" | awk -F. '{print $NF}' | sort | uniq -c | sort -rn | head -n 10
        echo
        echo "Top 20 Domains:"
        sort "$DOMAINS_FILE" | uniq -c | sort -rn | head -n 20
    } >> "$LOG_FILE"

    log "Detailed statistics appended to log file"
}

# Main execution
main() {
    trap 'rm -rf "$TEMP_DIR"' EXIT

    # Ensure logs directory exists
    mkdir -p "$LOGS_DIR"
    # Clear previous log file
    : > "$LOG_FILE"

    check_dependencies

    if [[ ! -f "$INPUT_FILE" ]]; then
        log "Error: Input file $INPUT_FILE not found!"
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    log "Starting blocklist generation..."

    mapfile -t input_lines < "$INPUT_FILE"
    local -r total_lines=${#input_lines[@]}
    log "Total lines in input file: $total_lines"

    log "Processing input file and extracting unique domains..."
    export -f process_chunk
    printf "%s\n" "${input_lines[@]}" | parallel --pipe -N1000 --block 1M process_chunk | \
        LC_ALL=C sort -u > "$DOMAINS_FILE"

    # If the previous blocklist exists, append its domains to the new list
    if [[ -f "$OUTPUT_FILE_HOSTS" ]]; then
        log "Appending previous blocklist entries to new blocklist..."
        grep -v '^#' "$OUTPUT_FILE_HOSTS" | awk '{print $2}' >> "$DOMAINS_FILE"
    fi

    # Remove duplicates from the combined list of previous and new domains
    log "Removing duplicates from combined domains..."
    LC_ALL=C sort -u "$DOMAINS_FILE" > "$COMBINED_DOMAINS_FILE"
    mv "$COMBINED_DOMAINS_FILE" "$DOMAINS_FILE"  # Move the sorted list back to the main domains file

    local -r domain_count=$(wc -l < "$DOMAINS_FILE")
    log "Unique domains extracted: $domain_count"

    generate_blocklist "hosts" "$OUTPUT_FILE_HOSTS"
    generate_blocklist "adguard" "$OUTPUT_FILE_ADGUARD"

    generate_stats

    log "Blocklist generation process finished successfully."
}

main "$@"
