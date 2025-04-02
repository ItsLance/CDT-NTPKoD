# Save as test_ntp.sh
# This file is for testing purposes.
# It's mostly used before and after the attack is executed to observe if NTP is functional
#!/bin/bash
TARGET="[target-ip]"

echo "Testing NTP server at $TARGET..."
for i in {1..10}; do
  echo -n "Test $i: "
  ntpdate -q -p 1 $TARGET | grep delay
  sleep 1
done
