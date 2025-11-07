#!/bin/bash

# Script to remove duplicate URLs from a formatted list
# Usage: ./dedupe-urls.sh [options]
# Options:
#   -i FILE    Input file (default: url-list.txt)
#   -o FILE    Output file (default: url-list-deduped.txt)
#   -s         Show statistics for each section
#   -v         Verbose mode (show duplicates being removed)
#   -h         Show help

# Default values
INPUT_FILE="url-list.txt"
OUTPUT_FILE="url-list-deduped.txt"
SHOW_STATS=false
VERBOSE=false

# Parse command line arguments
while getopts "i:o:svh" opt; do
    case $opt in
        i) INPUT_FILE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        s) SHOW_STATS=true ;;
        v) VERBOSE=true ;;
        h) 
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -i FILE    Input file (default: url-list.txt)"
            echo "  -o FILE    Output file (default: url-list-deduped.txt)"
            echo "  -s         Show statistics for each section"
            echo "  -v         Verbose mode (show duplicates being removed)"
            echo "  -h         Show this help"
            exit 0
            ;;
        \?) echo "Invalid option -$OPTARG" >&2; exit 1 ;;
    esac
done

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file '$INPUT_FILE' not found!"
    exit 1
fi

# Temporary files
TEMP_SEEN="/tmp/seen_urls_$$.txt"
TEMP_SECTION_STATS="/tmp/section_stats_$$.txt"
touch "$TEMP_SEEN"

# Variables for tracking
current_section=""
section_original=0
section_unique=0

# Function to print section statistics
print_section_stats() {
    if [ -n "$current_section" ] && [ "$SHOW_STATS" = true ]; then
        local removed=$((section_original - section_unique))
        echo "  Section: $current_section" >&2
        echo "    Original: $section_original, Unique: $section_unique, Removed: $removed" >&2
    fi
}

# Process the file
{
    while IFS= read -r line; do
        # Handle empty lines
        if [ -z "$line" ]; then
            echo ""
            continue
        fi
        
        # Handle comment/header lines
        if [[ "$line" =~ ^[[:space:]]*# ]]; then
            # Print stats for previous section if enabled
            print_section_stats
            
            # Reset counters for new section
            if [[ "$line" =~ ^#=+ ]]; then
                current_section=$(echo "$line" | sed 's/^#=*[[:space:]]*//;s/[[:space:]]*=*$//')
                section_original=0
                section_unique=0
            fi
            
            echo "$line"
            continue
        fi
        
        # Process URL lines
        url=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        
        # Skip empty URLs
        if [ -z "$url" ]; then
            continue
        fi
        
        # Count original URLs
        ((section_original++))
        
        # Check for duplicates
        if grep -Fxq "$url" "$TEMP_SEEN"; then
            # Found duplicate
            if [ "$VERBOSE" = true ]; then
                echo "  Removing duplicate: $url" >&2
            fi
        else
            # New unique URL
            echo "$url"
            echo "$url" >> "$TEMP_SEEN"
            ((section_unique++))
        fi
    done < "$INPUT_FILE"
    
    # Print stats for last section
    print_section_stats
} > "$OUTPUT_FILE"

# Clean up
rm -f "$TEMP_SEEN" "$TEMP_SECTION_STATS"

# Overall statistics
echo "========================================" >&2
echo "Deduplication Complete!" >&2
echo "========================================" >&2

ORIGINAL_TOTAL=$(grep -v '^#' "$INPUT_FILE" | grep -v '^[[:space:]]*$' | wc -l)
DEDUPED_TOTAL=$(grep -v '^#' "$OUTPUT_FILE" | grep -v '^[[:space:]]*$' | wc -l)
REMOVED_TOTAL=$((ORIGINAL_TOTAL - DEDUPED_TOTAL))

echo "Input file: $INPUT_FILE" >&2
echo "Output file: $OUTPUT_FILE" >&2
echo "Total original URLs: $ORIGINAL_TOTAL" >&2
echo "Total unique URLs: $DEDUPED_TOTAL" >&2
echo "Total duplicates removed: $REMOVED_TOTAL" >&2

if [ $REMOVED_TOTAL -gt 0 ]; then
    PERCENTAGE=$(echo "scale=2; $REMOVED_TOTAL * 100 / $ORIGINAL_TOTAL" | bc)
    echo "Reduction: ${PERCENTAGE}%" >&2
fi