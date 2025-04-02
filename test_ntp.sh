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

for i in {1..10}; do
    echo -n "Test $i: "
    timeout 3 ntpdate -q -p 1 $TARGET 2>&1 | grep -E "delay|timed out|no server suitable"
    
    # Capture exit status to indicate timeouts or errors
    STATUS=$?
    if [ $STATUS -ne 0 ]; then
        echo "  ERROR: NTP request failed with status $STATUS"
    fi
    
    sleep 1
done

echo "------------------------------------------------------------"
echo "NTP server test completed - $(date)"
echo "------------------------------------------------------------"
