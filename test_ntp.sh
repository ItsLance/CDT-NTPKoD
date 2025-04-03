#!/bin/bash

# Check if IP address was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

TARGET="$1"

echo "==== Basic NTP Server Check for $TARGET ===="

echo "== Installing necessary packages...==="
sudo apt install ntp sntp python3 pip iputils-ping ntpdate nano netcat-traditional netcat-openbsd nmap tcpdump
pip3 install scapy
sleep 3

# Check if NTP port is open using nmap (more reliable than nc)
echo "[1] Checking if NTP port is open..."
nmap -p 123 -sU $TARGET
sleep 10

# Try a simple ntpdate query
echo "[2] Testing with ntpdate (simple query)..."
ntpdate -q $TARGET
sleep 3

# Try a more detailed ntpdate query
echo "[3] Testing with ntpdate (detailed query)..."
ntpdate -d $TARGET
sleep 3

# Try ntpq peek command
echo "[3] Testing with ntpq...(likely to time out due to ntp.conf but still worth a shot)"
echo "rv" | ntpq -p $TARGET
sleep 5

echo "==== NTP Server Check completed ===="
