#!/bin/bash

set -e  # Exit on any error

LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
LINPEAS_FILE="linpeas.sh"
OUTPUT_FILE="linpeas.txt"

# Check if wget is installed
if ! command -v wget &> /dev/null; then
    echo "❌ wget is not installed. Please install wget and try again."
    exit 1
fi

echo "⬇️ Downloading linpeas..."
wget -q --show-progress "$LINPEAS_URL" -O "$LINPEAS_FILE"

# Check if download was successful
if [[ ! -f "$LINPEAS_FILE" ]]; then
    echo "❌ Failed to download linpeas.sh"
    exit 1
fi

echo "✅ Downloaded linpeas.sh"

# Make it executable
chmod +x "$LINPEAS_FILE"
echo "🔧 Made linpeas.sh executable"

# Run linpeas and save output
echo "🚀 Running linpeas..."
./"$LINPEAS_FILE" -a > "$OUTPUT_FILE"

echo "📄 Output saved to $OUTPUT_FILE"
