#!/bin/bash

# Array of URLs to fetch the domain lists
DOMAIN_LIST_URLS=(
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt"
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
)

# Specify the output file for the generated list
OUTPUT_FILE="xiaomi_ads_and_trackers_list.txt"

# Filter keywords (can be modified as needed)
FILTER_KEYWORDS=("xiaomi" "miui")

# Function to add header to the output file
add_header() {
    {
        echo "!"
        echo "! Title: Xiaomi ads and tracking"
        echo "! Description: Filter composed of several other filters (AdGuard DNS filter, HaGeZi's Pro++ DNS Blocklist, etc)"
        echo "! Homepage: https://github.com/fynks/blocklists"
        echo "! Last modified: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        echo "!"
        echo "! Compiled by @Fynks"
        echo "!"
    } > "$OUTPUT_FILE"
}

# Function to fetch and filter domains
fetch_and_filter() {
    local url=$1
    local temp_file=$2
    echo "Fetching domain list from $url..." >&2
    
    if ! DOMAIN_LIST=$(curl -s --max-time 30 "$url"); then
        echo "Failed to fetch domain list from $url" >&2
        return 1
    fi
    
    # Construct grep pattern from FILTER_KEYWORDS
    local grep_pattern=$(printf "|%s" "${FILTER_KEYWORDS[@]}")
    grep_pattern=${grep_pattern:1}  # Remove leading '|'
    
    echo "$DOMAIN_LIST" | grep -E "$grep_pattern" | while IFS= read -r domain; do
        # Remove the leading "||" and trailing "^" if present
        cleaned_domain=$(echo "$domain" | sed 's/^||//;s/\^$//')
        echo "$cleaned_domain" >> "$temp_file"
    done
}

# Function to clean up temporary files and handle exit
cleanup() {
    rm -f "$TEMP_FILE"
}
trap cleanup EXIT

# Backup existing output file if it exists
if [ -f "$OUTPUT_FILE" ]; then
    mv "$OUTPUT_FILE" "${OUTPUT_FILE}.bak"
    echo "Existing $OUTPUT_FILE backed up to ${OUTPUT_FILE}.bak" >&2
fi

# Create or clear the output file and add the header
add_header

# Temporary file to store all fetched and filtered domains
TEMP_FILE=$(mktemp) || { echo "Failed to create temporary file" >&2; exit 1; }

# Fetch and filter domains from each URL
total_urls=${#DOMAIN_LIST_URLS[@]}
for i in "${!DOMAIN_LIST_URLS[@]}"; do
    url="${DOMAIN_LIST_URLS[$i]}"
    echo "Processing URL $((i+1))/$total_urls" >&2
    fetch_and_filter "$url" "$TEMP_FILE" &
done

# Wait for all background processes to finish
wait

# Remove duplicates and append to the output file
if ! sort -u "$TEMP_FILE" >> "$OUTPUT_FILE"; then
    echo "Failed to sort and remove duplicates" >&2
    exit 1
fi

# Final message
if [ -s "$OUTPUT_FILE" ]; then
    echo "Generated list saved to $OUTPUT_FILE." >&2
    echo "Total unique domains: $(wc -l < "$OUTPUT_FILE")" >&2
else
    echo "No domains containing specified keywords found." >&2
fi