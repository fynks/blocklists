#!/usr/bin/env bash

set -euo pipefail

# Configuration
readonly INPUT_FILE="input.json"
readonly OUTPUT_DIR="../blocklists"
readonly LOGS_DIR="../.logs"
readonly OUTPUT_FILE_SIMPLE="${OUTPUT_DIR}/personal_blocklist_simple.txt"
readonly OUTPUT_FILE_ADGUARD="${OUTPUT_DIR}/personal_blocklist_adguard.txt"
readonly LOG_FILE="${LOGS_DIR}/personal_blocklist_generation.log"
readonly TEMP_DIR=$(mktemp -d)
readonly DOMAINS_FILE="${TEMP_DIR}/domains.txt"

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
        if [[ "$format" == "simple" ]]; then
            cat << EOF
# Title: Personal Blocklist (Simple Format)
# Description: Domains blocked based on personal preferences
# Last updated: $timestamp
# Number of unique domains: $domain_count
#
# Simple domain list format

EOF
            cat "$DOMAINS_FILE"
        else
            cat << EOF
! Title: Personal Blocklist (AdGuard/AdAway Format)
! Description: Domains blocked based on personal preferences
! Last updated: $timestamp
! Number of unique domains: $domain_count
!
! Compatible with AdGuard Android and AdAway
!
! Blocklist format: ||example.com^

EOF
            sed 's/^/||/' "$DOMAINS_FILE" | sed 's/$/^/'
        fi
    } > "$output_file"

    log "$format format blocklist written to $output_file"
}

# Function to generate detailed statistics
generate_stats() {
    log "Generating detailed statistics..."

    {
        echo "Blocklist Statistics"
        echo "===================="
        echo
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

    local -r domain_count=$(wc -l < "$DOMAINS_FILE")
    log "Unique domains extracted: $domain_count"

    generate_blocklist "simple" "$OUTPUT_FILE_SIMPLE"
    generate_blocklist "adguard" "$OUTPUT_FILE_ADGUARD"

    generate_stats

    log "Blocklist generation process finished successfully."
}

main "$@"
