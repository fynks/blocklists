#!/usr/bin/env bash
#
# list-to-hosts.sh - Convert URL list to hosts format blocklist
# Usage: ./list-to-hosts.sh [options]
#
# Options:
#   -s         Show per-section deduplication statistics
#   -v         Verbose mode (show duplicates being removed)
#   -h         Show this help
#
# This script reads domains from url-list.txt and generates a hosts format
# blocklist to personal.txt

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

# Script directory and file paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INPUT_FILE="${SCRIPT_DIR}/url-list.txt"
readonly OUTPUT_FILE="${SCRIPT_DIR}/../blocklists/personal.txt"
readonly EXTERNAL_LIST_URL="https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.xiaomi.txt"
readonly TEMP_FILE="$(mktemp)"
readonly TEMP_EXTERNAL="$(mktemp)"

# Cleanup temporary files on exit
trap 'rm -f "${TEMP_FILE}" "${TEMP_EXTERNAL}"' EXIT

# Print colored message
print_status() {
    local color=$1
    shift
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $*"
}

# Validate input file exists
validate_input() {
    if [[ ! -f "${INPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Input file not found: ${INPUT_FILE}"
        exit 1
    fi
    
    if [[ ! -s "${INPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Input file is empty: ${INPUT_FILE}"
        exit 1
    fi
}

# Print section statistics (if enabled)
print_section_stats() {
    local section_name="$1"
    local original="$2"
    local unique="$3"
    
    if [ -n "${section_name}" ] && [ "${SHOW_STATS}" = true ]; then
        local removed=$((original - unique))
        echo "  Section: ${section_name}" >&2
        echo "    Original: ${original}, Unique: ${unique}, Removed: ${removed}" >&2
    fi
}

# Extract and normalize domains with built-in deduplication
process_domains() {
    local total_original=0
    local total_unique=0
    local current_section=""
    local section_original=0
    local section_unique=0
    local temp_seen
    temp_seen="$(mktemp)"
    
    print_status "${YELLOW}" "Processing domains from ${INPUT_FILE}..."
    
    # Read file, trim whitespace, extract domains
    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Skip empty lines and markdown separators
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^[[:space:]]*-+[[:space:]]*$ ]] && continue
        
        # Handle comment lines
        if [[ "${line}" =~ ^[[:space:]]*# ]]; then
            # Detect section headers (e.g. #============ Name ============)
            if [[ "${line}" =~ ^#=+[[:space:]]* ]]; then
                # Print stats for previous section if enabled
                print_section_stats "${current_section}" "${section_original}" "${section_unique}"
                
                # Extract section name
                current_section="$(echo "${line}" | sed 's/^#=*[[:space:]]*//;s/[[:space:]]*=*$//')"
                section_original=0
                section_unique=0
            fi
            continue
        fi
        
        # Trim leading/trailing whitespace
        line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        
        # Skip if empty after trimming
        [[ -z "${line}" ]] && continue
        
        # Extract domain from URL or use as-is
        domain="${line}"
        
        # Remove protocol (http://, https://, etc.)
        domain="${domain#*://}"
        
        # Remove path, query string, and fragment
        domain="${domain%%/*}"
        domain="${domain%%\?*}"
        domain="${domain%%#*}"
        
        # Remove port number
        domain="${domain%%:*}"
        
        # Validate domain format (basic check)
        if [[ ! "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            print_status "${YELLOW}" "Skipping invalid domain: ${domain}"
            continue
        fi
        
        # Count as original
        total_original=$((total_original + 1))
        section_original=$((section_original + 1))
        
        # Check for duplicates using the extracted domain
        if grep -Fxq "${domain}" "${temp_seen}"; then
            if [ "${VERBOSE}" = true ]; then
                echo "  Removing duplicate domain: ${domain}" >&2
            fi
        else
            # New unique domain
            echo "${domain}" >> "${TEMP_FILE}"
            echo "${domain}" >> "${temp_seen}"
            total_unique=$((total_unique + 1))
            section_unique=$((section_unique + 1))
        fi
    done < "${INPUT_FILE}"
    
    # Print stats for last section
    print_section_stats "${current_section}" "${section_original}" "${section_unique}"
    
    # Cleanup
    rm -f "${temp_seen}"
    
    local duplicates=$((total_original - total_unique))
    print_status "${GREEN}" "Processed ${total_original} domains, ${total_unique} unique, ${duplicates} duplicates removed"
}

# Fetch and process external blocklist
fetch_external_list() {
    # Disabled: External list fetching is currently disabled
    print_status "${YELLOW}" "External list fetching is disabled, skipping..."
    return 0
}

# Generate hosts file
generate_hosts_file() {
    local output_dir
    output_dir="$(dirname "${OUTPUT_FILE}")"
    
    # Create output directory if it doesn't exist
    mkdir -p "${output_dir}"
    
    print_status "${YELLOW}" "Generating hosts file..."
    
    # Sort and remove duplicates first to get accurate count
    local sorted_temp="${TEMP_FILE}.sorted"
    sort -u "${TEMP_FILE}" > "${sorted_temp}"
    local unique_count
    unique_count=$(wc -l < "${sorted_temp}")
    
    # Get current date
    local current_date
    current_date=$(date '+%d-%m-%Y')
    
    # Generate hosts file with updated count
    {
        # Header
        echo "# Title: Personal Blocklist (Hosts Format)"
        echo "# Description: Domains blocked based on personal preferences"
        echo "# Total unique domains: ${unique_count}"
        echo "# Generated at: ${current_date}"
        echo "#"
        echo "# Hosts file format: 0.0.0.0 example.com"
        echo ""
        
        # Add domains with 0.0.0.0 prefix
        while IFS= read -r domain; do
            echo "0.0.0.0 ${domain}"
        done < "${sorted_temp}"
    } > "${OUTPUT_FILE}"
    
    # Cleanup sorted temp file
    rm -f "${sorted_temp}"
    
    local unique_count
    unique_count=$(grep -c '^0\.0\.0\.0' "${OUTPUT_FILE}" || true)
    
    print_status "${GREEN}" "Generated hosts file with ${unique_count} unique domains"
    print_status "${GREEN}" "Output: ${OUTPUT_FILE}"
}

# Validate output file
validate_output() {
    if [[ ! -f "${OUTPUT_FILE}" ]]; then
        print_status "${RED}" "Error: Failed to generate output file"
        exit 1
    fi
    
    # Check for proper hosts format
    if ! grep -q '^0\.0\.0\.0 ' "${OUTPUT_FILE}"; then
        print_status "${RED}" "Error: Output file does not contain valid hosts entries"
        exit 1
    fi
    
    print_status "${GREEN}" "Validation successful!"
}

# Main execution
main() {
    # Parse command line options
    while getopts "svh" opt; do
        case $opt in
            s) SHOW_STATS=true ;;
            v) VERBOSE=true ;;
            h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Reads domains from url-list.txt and generates a hosts format blocklist."
                echo ""
                echo "Options:"
                echo "  -s         Show per-section deduplication statistics"
                echo "  -v         Verbose mode (show duplicates being removed)"
                echo "  -h         Show this help"
                exit 0
                ;;
            \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
        esac
    done
    
    print_status "${GREEN}" "Starting hosts file generation..."
    
    validate_input
    process_domains
    fetch_external_list
    generate_hosts_file
    validate_output
    
    print_status "${GREEN}" "Done! Blocklist is ready to deploy."
}

# Run main function
main "$@"
