#!/bin/bash
# This is a simple diagnostic script from the attacker to the target to see if NTP is running and working
# USE: ./test_ntp.sh <IP ADDRESS>
# Example: ./test_ntp.sh 10.1.0.2

# Note: At times, [2] and [3] of the process may not working 100% of the time likely due to "noquery" in the ntp.conf
# of the server and may need to be run manually. It is still a good reference for necessary packages and commands to run.

# Author: Lance Cordova

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
echo "[4] Testing with ntpq...(likely to time out due to ntp.conf but still worth a shot)"
echo "rv" | ntpq -p $TARGET
sleep 5

echo "==== NTP Server Check completed ===="
