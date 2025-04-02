# This file is for testing purposes.
# It's mostly used before and after the attack is executed to observe if NTP is functional
#!/bin/bash

# Check if IP address was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target-ip>"
    echo "Example: $0 192.168.1.10"
    exit 1
fi

TARGET="$1"

echo "------------------------------------------------------------"
echo "Testing NTP server at $TARGET - $(date)"
echo "------------------------------------------------------------"

# Check if ntpdate is installed
if ! command -v ntpdate &> /dev/null; then
    echo "ERROR: ntpdate command not found. Installing..."
    sudo apt-get update && sudo apt-get install -y ntpdate
    if [ $? -ne 0 ]; then
        echo "Failed to install ntpdate. Try manually: sudo apt-get install ntpdate"
        exit 1
    fi
fi

# Try ping first to verify basic connectivity
echo "Verifying connectivity with ping..."
ping -c 3 $TARGET
if [ $? -ne 0 ]; then
    echo "WARNING: Cannot ping target. NTP may still work if ICMP is blocked."
else
    echo "Ping successful."
fi

# Check if port 123 is open
echo "Checking if NTP port is open..."
nc -zvw3 $TARGET 123
if [ $? -ne 0 ]; then
    echo "WARNING: Port 123 appears to be closed or filtered."
fi

echo "------------------------------------------------------------"
echo "Testing NTP responses..."
echo "------------------------------------------------------------"

# Try both ntpdate and ntpq for better diagnostics
for i in {1..5}; do
    echo -n "Test $i (ntpdate): "
    timeout 5 ntpdate -d -q $TARGET 2>&1 | grep -E "delay|offset|server|timed out|no server suitable"
    echo ""
    
    echo -n "Test $i (ntpq): "
    echo "rv" | timeout 3 ntpq -p $TARGET 2>&1 | grep -v "^"
    echo "------------------------------------------------------------"
    
    sleep 1
done

echo "Alternative test with ntplib (if available):"
if command -v python3 &> /dev/null; then
    # Try using Python's ntplib which sometimes works better
    python3 -c "
import ntplib
import sys
try:
    client = ntplib.NTPClient()
    response = client.request('$TARGET', version=3)
    print(f'Offset: {response.offset}')
    print(f'Delay: {response.delay}')
    print(f'Version: {response.version}')
    sys.exit(0)
except Exception as e:
    print(f'Error: {e}')
    sys.exit(1)
"
    if [ $? -eq 127 ]; then
        echo "Python ntplib not installed. Install with: pip3 install ntplib"
    fi
fi

echo "------------------------------------------------------------"
echo "Raw packet test using netcat:"
echo "------------------------------------------------------------"
# Send a basic NTP packet using netcat
echo -e "\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" | nc -u $TARGET 123 -w 3 > /tmp/ntp_response.bin
if [ -s /tmp/ntp_response.bin ]; then
    echo "Received response (hexdump):"
    hexdump -C /tmp/ntp_response.bin
else
    echo "No response received"
fi

echo "------------------------------------------------------------"
echo "NTP server test completed - $(date)"
echo "------------------------------------------------------------"
