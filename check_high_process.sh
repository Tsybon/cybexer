#!/bin/bash

# Set threshold for "high" PIDs (adjust as needed)
HIGH_PID_THRESHOLD=1000

# Find processes with names in square brackets and high PIDs
echo "Checking for suspicious processes with high PIDs in square brackets..."
echo "--------------------------------------------------------------------"

ps aux | awk -v threshold=$HIGH_PID_THRESHOLD '
  # Look for processes with names in square brackets
  $NF ~ /^\[.*\]$/ && $2 > threshold {
    printf "SUSPICIOUS PROCESS FOUND:\n"
    printf "PID: %s\n", $2
    printf "User: %s\n", $1
    printf "CPU%%: %s\n", $3
    printf "MEM%%: %s\n", $4
    printf "Process: %s\n", $NF
    printf "Running since: %s %s\n", $(NF-2), $(NF-1)
    printf "--------------------------------------------------------------------\n"
  }
'

# Alternative check using pgrep for processes in brackets
echo "Alternative check using pgrep:"
for pid in $(pgrep -f "^\[.*\]$"); do
  if [ "$pid" -gt "$HIGH_PID_THRESHOLD" ]; then
    echo "High PID process found: $pid - $(ps -p $pid -o comm=)"
    echo "Details: $(ps -p $pid -o user,pid,ppid,start,time,cmd | tail -n +2)"
  fi
done

echo "Scan complete."
