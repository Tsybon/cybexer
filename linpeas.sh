#!/bin/bash

set -e  # Exit immediately on error

LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
LINPEAS_FILE="linpeas.sh"
OUTPUT_FILE="linpeas.txt"

# Check if wget is available
if ! command -v wget &> /dev/null; then
    echo "[!] Error: wget is not installed. Please install it and try again."
    exit 1
fi

echo "[*] Downloading linpeas.sh from $LINPEAS_URL..."
wget "$LINPEAS_URL" -O "$LINPEAS_FILE"

# Check if the file was downloaded
if [[ ! -f "$LINPEAS_FILE" ]]; then
    echo "[!] Error: Download failed. linpeas.sh not found."
    exit 1
fi

echo "[+] linpeas.sh downloaded successfully."

# Make it executable
chmod +x "$LINPEAS_FILE"
echo "[+] linpeas.sh is now executable."

# Run the script and capture output
echo "[*] Running linpeas.sh with -a option..."
./"$LINPEAS_FILE" -a > "$OUTPUT_FILE"

echo "[✓] linpeas.sh completed. Output saved to $OUTPUT_FILE."
