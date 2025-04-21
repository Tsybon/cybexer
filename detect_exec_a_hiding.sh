#!/bin/bash

echo "[*] Scanning for suspicious exec -a style hidden processes..."

# Loop through all PIDs
for pid in $(ls /proc | grep '^[0-9]\+$'); do
    # Check if necessary files exist
    if [[ -r "/proc/$pid/cmdline" && -r "/proc/$pid/exe" ]]; then
        # Get actual executable path
        exe_path=$(readlink -f "/proc/$pid/exe")
        
        # Get the full command line
        cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline)

        # Get the apparent process name (first word)
        apparent_name=$(echo "$cmdline" | awk '{print $1}')
        
        # Compare the process name vs the actual executable
        if [[ "$apparent_name" != "$exe_path" ]]; then
            echo "[!] Suspicious process:"
            echo "    PID: $pid"
            echo "    Cmdline: $cmdline"
            echo "    Executable: $exe_path"
            echo "    Apparent Name: $apparent_name"
            echo ""
        fi
    fi
done

echo "[*] Scan complete."
