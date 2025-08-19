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

# Constants
readonly TEMP_DIR=$(mktemp -d)
readonly SCRIPT_START_TIME=$(date +%s)
readonly REQUIRED_DEPS=("jq" "parallel")
readonly MIN_DOMAIN_LENGTH=1
readonly MAX_DOMAIN_LENGTH=253

# Cleanup function
cleanup() {
    local exit_code=$?
    rm -rf "$TEMP_DIR"
    exit $exit_code
}
trap cleanup EXIT

# Enhanced logging with different levels
log() {
    local level="${2:-INFO}"
    local timestamp
    timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p")
    local log_line="[$timestamp] [$level] $1"
    echo "$log_line" | tee -a "${PATHS[LOG_FILE]}"
}

log_info() { log "$1" "INFO"; }
log_warn() { log "$1" "WARN"; }
log_error() { log "$1" "ERROR"; }

# Enhanced dependency checking
check_dependencies() {
    local missing_deps=()
    
    for dep in "${REQUIRED_DEPS[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}. Please install them to run this script."
        exit 1
    fi
    
    # Check parallel version for compatibility
    local parallel_version
    parallel_version=$(parallel --version 2>/dev/null | head -n1 | awk '{print $3}')
    if [[ -n "$parallel_version" && "$parallel_version" -lt 20160122 ]]; then
        log_warn "Old version of GNU parallel detected. Some features may not work correctly."
    fi
}

# Simplified domain validation
validate_domain() {
    local domain="$1"
    
    # Check if domain is empty
    if [[ -z "$domain" ]]; then
        return 1
    fi
    
    local length=${#domain}
    
    # Length checks
    if [[ $length -lt $MIN_DOMAIN_LENGTH || $length -gt $MAX_DOMAIN_LENGTH ]]; then
        return 1
    fi
    
    # Basic format validation - more permissive
    if [[ "$domain" =~ ^[a-zA-Z0-9._-]+[.][a-zA-Z0-9._-]+$ ]]; then
        # Must contain at least one dot and not start/end with special chars
        if [[ ! "$domain" =~ ^[.-] ]] && [[ ! "$domain" =~ [.-]$ ]]; then
            return 0
        fi
    fi
    
    return 1
}

# Optimized chunk processing with better error handling
process_chunk() {
    # Process JSON and filter domains
    jq -r 'select(.status == "REQUEST_BLOCKED" and .device == "Phone") | .domain // empty' 2>/dev/null || true
}

# Enhanced blocklist generation with better formatting
generate_blocklist() {
    local -r format="$1"
    local -r output_file="$2"
    local -r domain_count="$3"
    local -r timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")
    local -r license_header="# License: MIT
# This blocklist is provided free of charge and without warranty.
# Use at your own risk."

    log_info "Generating $format format blocklist with $domain_count domains..."

    {
        if [[ "$format" == "hosts" ]]; then
            cat << EOF
# Title: Personal Blocklist (Hosts Format)
# Description: Domains blocked based on personal preferences
# Last updated: $timestamp
# Number of unique domains: $domain_count
# Homepage: https://github.com/fynks/blocklists
$license_header
#
# Hosts file format: 0.0.0.0 example.com

EOF
            stdbuf -oL awk '{print "0.0.0.0 " $0}'
        else
            cat << EOF
! Title: Personal Blocklist (AdGuard Format)
! Description: Domains blocked based on personal preferences
! Last updated: $timestamp
! Number of unique domains: $domain_count
! Homepage: https://github.com/fynks/blocklists
! License: MIT
!
! Blocklist format: ||example.com^

EOF
            stdbuf -oL awk '{print "||" $0 "^"}'
        fi
    } > "$output_file"

    # Verify file was created successfully
    if [[ ! -s "$output_file" ]]; then
        log_error "Failed to create $format format blocklist"
        return 1
    fi

    log_info "$format format blocklist written to $output_file ($domain_count domains)"
}

# Enhanced statistics generation with better formatting
generate_stats() {
    local -r domains_file="$1"
    local -r elapsed_time=$(($(date +%s) - SCRIPT_START_TIME))
    
    log_info "Generating detailed statistics..."

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
        awk -F. 'NF>=2 {print $(NF-1)"."$NF}' "$domains_file" | LC_ALL=C sort | uniq -c | sort -rn | head -n 20 | awk '{printf "  %-6s %s\n", $1, $2}'
        echo
        echo "Domain Length Distribution:"
        awk '{print length($0)}' "$domains_file" | LC_ALL=C sort -n | uniq -c | awk '{printf "  %2d chars: %d domains\n", $2, $1}' | tail -n 15
        echo
        echo "Summary:"
        echo "  - Average domain length: $(awk '{sum+=length($0); count++} END {printf "%.1f", sum/count}' "$domains_file") characters"
        echo "  - Shortest domain: $(awk 'NR==1{min=length($0)} length($0)<min{min=length($0)} END{print min}' "$domains_file") characters"
        echo "  - Longest domain: $(awk 'NR==1{max=length($0)} length($0)>max{max=length($0)} END{print max}' "$domains_file") characters"
    } >> "${PATHS[LOG_FILE]}"

    log_info "Detailed statistics appended to log file (processing took ${elapsed_time}s)"
}

# Main function with enhanced error handling and progress tracking
main() {
    # Create directories and initialize log
    mkdir -p "${PATHS[LOGS_DIR]}" "${PATHS[OUTPUT_DIR]}"
    : > "${PATHS[LOG_FILE]}"

    log_info "Starting personal blocklist generation..."

    check_dependencies

    # Validate input file
    if [[ ! -f "${PATHS[INPUT_FILE]}" ]]; then
        log_error "Input file ${PATHS[INPUT_FILE]} not found!"
        exit 1
    elif [[ ! -s "${PATHS[INPUT_FILE]}" ]]; then
        log_error "Input file ${PATHS[INPUT_FILE]} is empty!"
        exit 1
    fi

    local -r input_lines=$(wc -l < "${PATHS[INPUT_FILE]}")
    log_info "Processing $input_lines lines from input file..."

    # Process input file with better error handling and progress indication
    log_info "Extracting domains from JSON data..."
    
    export -f process_chunk
    if ! stdbuf -oL < "${PATHS[INPUT_FILE]}" parallel --pipe -N1000 --block 1M --progress process_chunk > "$TEMP_DIR/new_domains.txt" 2>/dev/null; then
        log_warn "Some parallel processing errors occurred, continuing with available data..."
    fi

    # Debug: Check what we got from processing
    local extracted_count
    extracted_count=$(wc -l < "$TEMP_DIR/new_domains.txt" 2>/dev/null || echo 0)
    log_info "Extracted $extracted_count raw domains"
    
    # Show sample of extracted domains for debugging
    if [[ $extracted_count -gt 0 ]]; then
        log_info "Sample of extracted domains:"
        head -n 5 "$TEMP_DIR/new_domains.txt" | while read -r line; do
            log_info "  $line"
        done
    fi

    # Remove empty lines and sort with progress tracking
    log_info "Processing and deduplicating domains..."
    grep -v '^$' "$TEMP_DIR/new_domains.txt" 2>/dev/null | LC_ALL=C sort -u > "$TEMP_DIR/domains.txt" 2>/dev/null || true

    # Debug: Check domains after basic processing
    local processed_count
    processed_count=$(wc -l < "$TEMP_DIR/domains.txt" 2>/dev/null || echo 0)
    log_info "After deduplication: $processed_count domains"

    # Merge with existing blocklist if it exists
    if [[ -f "${PATHS[OUTPUT_FILE_HOSTS]}" && -s "${PATHS[OUTPUT_FILE_HOSTS]}" ]]; then
        log_info "Merging with existing blocklist entries..."
        grep -v '^#' "${PATHS[OUTPUT_FILE_HOSTS]}" | awk '$2 {print $2}' >> "$TEMP_DIR/domains.txt"
    fi

    # Final deduplication and sorting
    LC_ALL=C sort -u "$TEMP_DIR/domains.txt" > "$TEMP_DIR/combined_domains.txt" 2>/dev/null || true

    local -r domain_count=$(wc -l < "$TEMP_DIR/combined_domains.txt" 2>/dev/null || echo 0)
    
    if [[ $domain_count -eq 0 ]]; then
        log_warn "No valid domains found to process!"
        log_info "Blocklist generation completed with no domains."
        
        # Create empty blocklist files with headers
        local timestamp
        timestamp=$(TZ="Asia/Karachi" date +"%Y-%m-%d %I:%M:%S %p %Z")
        
        # Create empty hosts file
        cat > "${PATHS[OUTPUT_FILE_HOSTS]}" << EOF
# Title: Personal Blocklist (Hosts Format)
# Description: Domains blocked based on personal preferences
# Last updated: $timestamp
# Number of unique domains: 0
# Homepage: https://github.com/fynks/blocklists
# License: MIT
# This blocklist is provided free of charge and without warranty.
# Use at your own risk.
#
# Hosts file format: 0.0.0.0 example.com

EOF
        
        # Create empty AdGuard file
        cat > "${PATHS[OUTPUT_FILE_ADGUARD]}" << EOF
! Title: Personal Blocklist (AdGuard Format)
! Description: Domains blocked based on personal preferences
! Last updated: $timestamp
! Number of unique domains: 0
! Homepage: https://github.com/fynks/blocklists
! License: MIT
!
! Blocklist format: ||example.com^

EOF
        
        log_info "Created empty blocklist files with headers"
        exit 0
    fi

    log_info "Processing $domain_count unique domains..."

    # Generate both formats in parallel with proper error handling
    local failed_generations=0
    
    generate_blocklist "hosts" "${PATHS[OUTPUT_FILE_HOSTS]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" || ((failed_generations++))
    generate_blocklist "adguard" "${PATHS[OUTPUT_FILE_ADGUARD]}" "$domain_count" < "$TEMP_DIR/combined_domains.txt" || ((failed_generations++))

    if [[ $failed_generations -gt 0 ]]; then
        log_error "Failed to generate $failed_generations blocklist format(s)"
        exit 1
    fi

    generate_stats "$TEMP_DIR/combined_domains.txt"

    log_info "Blocklist generation completed successfully!"
    log_info "Files generated:"
    log_info "  - Hosts format: ${PATHS[OUTPUT_FILE_HOSTS]} ($(stat -f%z "${PATHS[OUTPUT_FILE_HOSTS]}" 2>/dev/null || stat -c%s "${PATHS[OUTPUT_FILE_HOSTS]}" 2>/dev/null) bytes)"
    log_info "  - AdGuard format: ${PATHS[OUTPUT_FILE_ADGUARD]} ($(stat -f%z "${PATHS[OUTPUT_FILE_ADGUARD]}" 2>/dev/null || stat -c%s "${PATHS[OUTPUT_FILE_ADGUARD]}" 2>/dev/null) bytes)"
}

# Run main function with argument parsing
main "$@"