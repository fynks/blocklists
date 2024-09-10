#!/usr/bin/env bash

set -euo pipefail

# Get the absolute path of the script's directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
readonly OUTPUT_DIR="${SCRIPT_DIR}/../blocklists"
readonly LOGS_DIR="${SCRIPT_DIR}/../.logs"
readonly OUTPUT_FILE_XIAOMI_ADGUARD="${OUTPUT_DIR}/xiaomi_blocklist_adguard.txt"
readonly OUTPUT_FILE_XIAOMI_SIMPLE="${OUTPUT_DIR}/xiaomi_blocklist_simple.txt"
readonly LOG_FILE="${LOGS_DIR}/xiaomi_blocklist_generation.log"
readonly TEMP_FILE=$(mktemp)
readonly FILTER_KEYWORDS=("xiaomi" "miui")
readonly DOMAIN_LIST_URLS=(
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt"
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
)

# Function to log messages
log() {
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    printf "[%s] %s\n" "$timestamp" "$1" | tee -a "$LOG_FILE"
}

# Function to add header to the output file
add_header() {
    local format="$1"
    local domain_count="$2"
    local timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")
    log "Adding header to $format format blocklist"

    {
        echo "! Title: Xiaomi Ads and Tracking Blocklist"
        echo "! Description: Domains related to Xiaomi ads and tracking, compiled from multiple sources."
        echo "! Last updated: $timestamp"
        echo "! Number of unique domains: $domain_count"
        echo "!"
        echo "! Sources:"
        for url in "${DOMAIN_LIST_URLS[@]}"; do
            echo "! - $url"
        done
        echo "!"
        echo "! Maintained by @Fynks"
        echo "!"
        if [[ "$format" == "adguard" ]]; then
            echo "! Blocklist format: ||example.com^"
        fi
        echo
    } > "${OUTPUT_DIR}/xiaomi_blocklist_${format}.txt"
}

# Function to fetch and filter domains from a URL
fetch_and_filter() {
    local url="$1"
    log "Fetching domain list from $url"

    if ! DOMAIN_LIST=$(curl -s --max-time 30 "$url"); then
        log "Error: Failed to fetch domain list from $url"
        return 1
    fi

    local grep_pattern=$(printf "|%s" "${FILTER_KEYWORDS[@]}")
    grep_pattern=${grep_pattern:1}  # Remove leading '|'

    echo "$DOMAIN_LIST" | grep -E "$grep_pattern" | while IFS= read -r domain; do
        cleaned_domain=$(echo "$domain" | sed 's/^||//;s/\^$//')
        echo "$cleaned_domain" >> "$TEMP_FILE"
    done
}

# Function to generate Xiaomi-specific blocklist
generate_xiaomi_blocklist() {
    log "Starting Xiaomi blocklist generation..."

    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$LOGS_DIR"
    # Clear previous log file
    : > "$LOG_FILE"

    # Fetch and filter domains from each URL
    for url in "${DOMAIN_LIST_URLS[@]}"; do
        fetch_and_filter "$url" &
    done
    wait

    # Remove duplicates and sort
    sort -u "$TEMP_FILE" > "${TEMP_FILE}_sorted"

    local domain_count=$(wc -l < "${TEMP_FILE}_sorted")

    # Add header for both AdGuard and Simple formats
    add_header "adguard" "$domain_count"
    add_header "simple" "$domain_count"

    # Format the blocklist entries in AdGuard format
    sed 's/^/||/;s/$/^/' "${TEMP_FILE}_sorted" >> "$OUTPUT_FILE_XIAOMI_ADGUARD"
    # Copy the domains directly for the simple format blocklist
    cat "${TEMP_FILE}_sorted" >> "$OUTPUT_FILE_XIAOMI_SIMPLE"

    log "Xiaomi blocklist generated: $OUTPUT_FILE_XIAOMI_ADGUARD (AdGuard format)"
    log "Xiaomi blocklist generated: $OUTPUT_FILE_XIAOMI_SIMPLE (Simple format)"
    log "Total unique domains: $domain_count"
}

# Cleanup function
cleanup() {
    rm -f "$TEMP_FILE" "${TEMP_FILE}_sorted"
    log "Temporary files cleaned up"
}
trap cleanup EXIT

# Main execution
main() {
    log "Initializing Xiaomi blocklist generator"
    generate_xiaomi_blocklist
    log "Xiaomi blocklist generation completed"
}

main "$@"
