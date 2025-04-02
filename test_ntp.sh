#!/bin/bash

# Check if IP address was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

TARGET="$1"

echo "==== Basic NTP Server Check for $TARGET ===="

# Check if NTP port is open using nmap (more reliable than nc)
echo "[1] Checking if NTP port is open..."
nmap -p 123 -sU $TARGET

# Try a simple ntpdate query
echo "[2] Testing with ntpdate..."
ntpdate -q -d $TARGET

# Try ntpq peek command
echo "[3] Testing with ntpq..."
echo "rv" | ntpq -p $TARGET

echo "==== NTP Server Check completed ===="
