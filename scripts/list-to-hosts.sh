#!/usr/bin/env bash
#
# list-to-hosts.sh - Convert URL list to hosts format blocklist
# Usage: ./list-to-hosts.sh
#
# This script reads domains from url-list.txt and generates a hosts format
# blocklist similar to personal_blocklist_hosts.txt

set -euo pipefail  # Exit on error, undefined variables, and pipe failures
IFS=$'\n\t'        # Set safer Internal Field Separator

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Script directory and file paths
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INPUT_FILE="${SCRIPT_DIR}/url-list.txt"
readonly OUTPUT_FILE="${SCRIPT_DIR}/../blocklists/personal_blocklist_hosts.txt"
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

# Extract and normalize domains
process_domains() {
    local domain_count=0
    
    print_status "${YELLOW}" "Processing domains from ${INPUT_FILE}..."
    
    # Read file, remove comments and empty lines, trim whitespace, extract domains
    while IFS= read -r line || [[ -n "${line}" ]]; do
        # Skip empty lines, comments (### or ---), and markdown separators
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^[[:space:]]*# ]] && continue
        [[ "${line}" =~ ^[[:space:]]*-+[[:space:]]*$ ]] && continue
        
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
        
        # Remove 'www.' prefix if present (optional, preserves original behavior)
        # domain="${domain#www.}"
        
        # Validate domain format (basic check)
        if [[ "${domain}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            echo "${domain}" >> "${TEMP_FILE}"
            domain_count=$((domain_count + 1))
        else
            print_status "${YELLOW}" "Skipping invalid domain: ${domain}"
        fi
    done < "${INPUT_FILE}"
    
    print_status "${GREEN}" "Processed ${domain_count} domains from local file (including duplicates)"
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
