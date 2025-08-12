#!/usr/bin/env bash

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUTPUT_DIR="${SCRIPT_DIR}/../blocklists"
readonly LOGS_DIR="${SCRIPT_DIR}/../.logs"
readonly OUTPUT_FILE_XIAOMI_ADGUARD="${OUTPUT_DIR}/xiaomi_blocklist_adguard.txt"
readonly OUTPUT_FILE_XIAOMI_HOSTS="${OUTPUT_DIR}/xiaomi_blocklist_hosts.txt"
readonly LOG_FILE="${LOGS_DIR}/xiaomi_blocklist_generation.log"
readonly TEMP_DIR=$(mktemp -d)
readonly FILTER_KEYWORDS=("xiaomi" "miui" "hyperos" "micloud")
readonly XIAOMI_SPECIFIC_URL="https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.xiaomi.txt"
readonly DOMAIN_LIST_URLS=(
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt"
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/MobileFilter/sections/adservers.txt"
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt"
)

trap 'rm -rf "$TEMP_DIR"' EXIT

log() {
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    printf "[%s] %s\n" "$timestamp" "$1" | tee -a "$LOG_FILE"
}

add_header() {
    local format="$1"
    local domain_count="$2"
    local timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")
    log "Adding header to $format format blocklist"

    {
        echo "# Title: Xiaomi Ads and Tracking Blocklist"
        echo "# Description: Domains related to Xiaomi ads and tracking, compiled from multiple sources."
        echo "# Last updated: $timestamp"
        echo "# Number of unique domains: $domain_count"
        echo "#"
        echo "# Sources:"
        echo "# - $XIAOMI_SPECIFIC_URL"
        for url in "${DOMAIN_LIST_URLS[@]}"; do
            echo "# - $url"
        done
        echo "#"
        echo "#"
        if [[ "$format" == "adguard" ]]; then
            echo "# Blocklist format: ||example.com^"
        elif [[ "$format" == "hosts" ]]; then
            echo "# Hosts file format: 0.0.0.0 example.com"
        fi
        echo
    } > "${OUTPUT_DIR}/xiaomi_blocklist_${format}.txt"
}

fetch_and_filter() {
    local url="$1"
    local output_file="$2"
    log "Fetching domain list from $url"

    if ! curl -s --max-time 30 --retry 3 "$url" | \
        grep -E "$(IFS='|'; echo "${FILTER_KEYWORDS[*]}")" | \
        grep -v '^[#!]' | \
        grep -v '^\$app=' | \
        sed 's/^||//;s/\^$//' | \
        grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' > "$output_file"; then
        log "Error: Failed to fetch domain list from $url"
        return 1
    fi
}

fetch_xiaomi_specific() {
    local output_file="$1"
    log "Fetching all domains from Xiaomi-specific URL: $XIAOMI_SPECIFIC_URL"

    if ! curl -s --max-time 30 --retry 3 "$XIAOMI_SPECIFIC_URL" | \
        grep -v '^[#!]' | \
        grep -v '^\$app=' | \
        sed 's/^||//;s/\^$//' | \
        grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' > "$output_file"; then
        log "Error: Failed to fetch domain list from $XIAOMI_SPECIFIC_URL"
        return 1
    fi
}

generate_xiaomi_blocklist() {
    log "Starting Xiaomi blocklist generation..."

    mkdir -p "$OUTPUT_DIR" "$LOGS_DIR"
    : > "$LOG_FILE"

    fetch_xiaomi_specific "${TEMP_DIR}/xiaomi_specific.txt" &

    for url in "${DOMAIN_LIST_URLS[@]}"; do
        fetch_and_filter "$url" "${TEMP_DIR}/$(basename "$url").txt" &
    done
    wait

    sort -u "${TEMP_DIR}"/*.txt > "${TEMP_DIR}/sorted_unique.txt"

    local domain_count=$(wc -l < "${TEMP_DIR}/sorted_unique.txt")

    add_header "adguard" "$domain_count"
    add_header "hosts" "$domain_count"

    sed 's/^/||/;s/$/^/' "${TEMP_DIR}/sorted_unique.txt" >> "$OUTPUT_FILE_XIAOMI_ADGUARD"
    sed 's/^/0.0.0.0 /' "${TEMP_DIR}/sorted_unique.txt" >> "$OUTPUT_FILE_XIAOMI_HOSTS"

    log "Xiaomi blocklist generated: $OUTPUT_FILE_XIAOMI_ADGUARD (AdGuard format)"
    log "Xiaomi blocklist generated: $OUTPUT_FILE_XIAOMI_HOSTS (Hosts format)"
    log "Total unique domains: $domain_count"
}

main() {
    log "Initializing Xiaomi blocklist generator"
    generate_xiaomi_blocklist
    log "Xiaomi blocklist generation completed"
}

main "$@"