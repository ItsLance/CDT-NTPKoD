#!/bin/bash

# NTP Vulnerable Setup Script for Ubuntu
# This script sets up an NTP server vulnerable to CVE-2016-9311 for educational testing
# Author: Lance Cordova
# WARNING: For use in isolated lab environments only

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display banner
display_banner() {
    echo -e "${RED}"
    echo "╔═╗╔═╗╔╦╗╦ ╦╔═╗  ╦  ╦╦ ╦╦  ╔╗╔╔═╗╦═╗╔═╗╔╗ ╦  ╔═╗  ╔╗╔╔╦╗╔═╗"
    echo "╚═╗║╣  ║ ║ ║╠═╝  ╚╗╔╝║ ║║  ║║║║╣ ╠╦╝╠═╣╠╩╗║  ║╣   ║║║ ║ ╠═╝"
    echo "╚═╝╚═╝ ╩ ╚═╝╩    ╚╝ ╚═╝╩═╝╝╚╝╚═╝╩╚═╚═╝╚═╝╩═╝╚═╝  ╝╚╝ ╩ ╩  "
    echo -e "${NC}"
    echo -e "${YELLOW}This script sets up an NTP server vulnerable to CVE-2016-9311${NC}"
    echo -e "${RED}WARNING: FOR EDUCATIONAL USE IN ISOLATED LAB ENVIRONMENTS ONLY${NC}"
    echo -e "${RED}DO NOT EXPOSE THIS SERVER TO UNTRUSTED NETWORKS${NC}"
    echo ""
}

# Function to check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Function to check Ubuntu version
check_ubuntu() {
    if [ -f /etc/lsb-release ]; then
        source /etc/lsb-release
        echo -e "${BLUE}[*] Detected Ubuntu ${DISTRIB_RELEASE}${NC}"
    else
        echo -e "${YELLOW}[!] This script is optimized for Ubuntu. Your system may not be fully compatible.${NC}"
    fi
}

# Function to check if Docker is installed
check_docker() {
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}[+] Docker is installed${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Docker is not installed${NC}"
        return 1
    fi
}

# Function to install Docker
install_docker() {
    echo -e "${BLUE}[*] Installing Docker...${NC}"
    
    # Update package index
    apt-get update
    
    # Install prerequisites
    apt-get install -y apt-transport-https ca-certificates curl software-properties-common
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
    
    # Add Docker repository
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    
    # Update package index again
    apt-get update
    
    # Install Docker CE
    apt-get install -y docker-ce
    
    # Check if Docker was installed successfully
    if command -v docker &> /dev/null; then
        echo -e "${GREEN}[+] Docker installed successfully${NC}"
        return 0
    else
        echo -e "${RED}[!] Failed to install Docker${NC}"
        return 1
    fi
}

# Function to backup existing NTP configuration
backup_existing_config() {
    echo -e "${BLUE}[*] Backing up existing NTP configuration...${NC}"
    
    # Create backup directory
    mkdir -p /root/ntp-backup
    
    # Backup NTP configuration if it exists
    if [ -f /etc/ntp.conf ]; then
        cp /etc/ntp.conf /root/ntp-backup/ntp.conf.bak
        echo -e "${GREEN}[+] Backed up /etc/ntp.conf${NC}"
    fi
    
    # Backup NTP service file if it exists
    if [ -f /etc/systemd/system/ntp.service ]; then
        cp /etc/systemd/system/ntp.service /root/ntp-backup/ntp.service.bak
        echo -e "${GREEN}[+] Backed up ntp.service${NC}"
    elif [ -f /lib/systemd/system/ntp.service ]; then
        cp /lib/systemd/system/ntp.service /root/ntp-backup/ntp.service.bak
        echo -e "${GREEN}[+] Backed up ntp.service${NC}"
    fi
    
    # Save installed NTP version information
    if command -v ntpd &> /dev/null; then
        ntpd --version > /root/ntp-backup/ntp-version.bak 2>&1
        echo -e "${GREEN}[+] Saved NTP version information${NC}"
    fi
    
    echo -e "${GREEN}[+] Backup completed to /root/ntp-backup/${NC}"
}

# Function to stop existing NTP services
stop_existing_ntp() {
    echo -e "${BLUE}[*] Stopping existing NTP services...${NC}"
    
    # Stop and disable NTP service if it exists
    if systemctl is-active --quiet ntp; then
        systemctl stop ntp
        systemctl disable ntp
        echo -e "${GREEN}[+] Stopped and disabled NTP service${NC}"
    elif systemctl is-active --quiet ntpd; then
        systemctl stop ntpd
        systemctl disable ntpd
        echo -e "${GREEN}[+] Stopped and disabled NTPD service${NC}"
    else
        echo -e "${YELLOW}[*] No active NTP service found${NC}"
    fi
    
    # Kill any remaining NTP processes
    if pgrep ntpd > /dev/null; then
        pkill ntpd
        echo -e "${GREEN}[+] Killed remaining NTP processes${NC}"
    fi
}

# Function to set up vulnerable NTP directly on the host
setup_direct_ntp() {
    echo -e "${BLUE}[*] Setting up vulnerable NTP directly on the host...${NC}"
    
    # Remove any existing NTP installation
    apt-get remove --purge -y ntp ntpdate &>/dev/null
    
    # Install NTP 4.2.8p8 package
    echo -e "${BLUE}[*] Installing NTP package...${NC}"
    apt-get update
    apt-get install -y ntp
    
    # Create vulnerable NTP configuration
    echo -e "${BLUE}[*] Creating vulnerable NTP configuration...${NC}"
    cat > /etc/ntp.conf << 'EOF'
# Basic NTP Configuration with vulnerable settings

# Default restrictions (allow everything for testing)
restrict default kod nomodify notrap nopeer

# Allow localhost full access
restrict 127.0.0.1
restrict ::1

# Server configuration - use local clock as fallback
server 127.127.1.0
fudge 127.127.1.0 stratum 10

# External servers
server 0.pool.ntp.org
server 1.pool.ntp.org
server 2.pool.ntp.org
server 3.pool.ntp.org

# Enable mode 6 and 7 (vulnerable)
enable mode7
enable stats
enable monitor

# Drift file
driftfile /var/lib/ntp/ntp.drift

# Statistics directory
statsdir /var/log/ntpstats/
statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable

# Log file
logfile /var/log/ntp.log
EOF
    
    # Create necessary directories
    mkdir -p /var/lib/ntp
    mkdir -p /var/log/ntpstats
    touch /var/log/ntp.log
    
    # Set proper permissions
    chown -R ntp:ntp /var/lib/ntp
    chown -R ntp:ntp /var/log/ntpstats
    chown ntp:ntp /var/log/ntp.log
    
    # Restart NTP service
    echo -e "${BLUE}[*] Starting NTP service...${NC}"
    systemctl restart ntp
    
    # Check if service is running
    if systemctl is-active --quiet ntp; then
        echo -e "${GREEN}[+] NTP service started successfully${NC}"
    else
        echo -e "${RED}[!] Failed to start NTP service${NC}"
        systemctl status ntp
    fi
    
    return 0
}

# Function to create a simple Python script to make the server vulnerable
create_vulnerability_script() {
    echo -e "${BLUE}[*] Creating vulnerability simulation script...${NC}"
    
    # Create a directory for the script
    mkdir -p /opt/ntp-vuln
    
    # Create the Python script
    cat > /opt/ntp-vuln/make_vulnerable.py << 'EOF'
#!/usr/bin/env python3
"""
NTP Vulnerability Simulator for CVE-2016-9311
This script simulates the trap vulnerability by responding to specific NTP queries
"""

import socket
import struct
import time
import threading
import sys
import os

# NTP constants
NTP_PORT = 123
MODE_CLIENT = 3
MODE_SERVER = 4
NTP_VERSION = 4
NTP_HEADER_SIZE = 48

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    sock.bind(('0.0.0.0', NTP_PORT))
    print(f"[+] Listening on UDP port {NTP_PORT}")
except PermissionError:
    print(f"[!] Error: Need root privileges to bind to port {NTP_PORT}")
    sys.exit(1)
except OSError as e:
    print(f"[!] Error binding to port {NTP_PORT}: {e}")
    print("[!] The port might be in use by another NTP service.")
    print("[!] Stop any running NTP services first.")
    sys.exit(1)

def create_response(data, addr):
    """Create a response packet for the given request"""
    # Extract the first byte to get the mode and version
    first_byte = data[0]
    version = (first_byte >> 3) & 0x7
    mode = first_byte & 0x7
    
    # Only respond to client mode packets
    if mode != MODE_CLIENT:
        return None
    
    # Create response packet
    resp = bytearray(NTP_HEADER_SIZE)
    
    # Set version and mode (4 = server)
    resp[0] = (version << 3) | MODE_SERVER
    
    # Copy the rest of the header from the request
    for i in range(1, 8):
        resp[i] = data[i]
    
    # Set reference timestamp (current time)
    now = int(time.time())
    resp[16:20] = struct.pack('>I', now)
    
    # If this is a "readvar" or "trap" query, add vulnerable data
    if len(data) > 48 and b"trap" in data:
        print(f"[!] Detected trap query from {addr[0]}:{addr[1]}")
        # Add vulnerable trap data
        trap_data = b"trap=127.0.0.1,127.0.0.1.2,127.0.0.1.3"
        resp += trap_data
    
    return resp

def handle_ntp_packets():
    """Main loop to handle incoming NTP packets"""
    print("[*] Vulnerability simulator running. Press Ctrl+C to stop.")
    
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"[*] Received {len(data)} bytes from {addr[0]}:{addr[1]}")
            
            response = create_response(data, addr)
            if response:
                sock.sendto(response, addr)
                print(f"[*] Sent {len(response)} bytes response to {addr[0]}:{addr[1]}")
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root")
        sys.exit(1)
        
    # Start handling packets
    handle_ntp_packets()
EOF
    
    # Make the script executable
    chmod +x /opt/ntp-vuln/make_vulnerable.py
    
    # Create a systemd service for the script
    cat > /etc/systemd/system/ntp-vuln-sim.service << 'EOF'
[Unit]
Description=NTP Vulnerability Simulator
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ntp-vuln/make_vulnerable.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}[+] Vulnerability simulation script created${NC}"
    return 0
}

# Function to verify NTP setup
verify_ntp_setup() {
    echo -e "${BLUE}[*] Verifying NTP setup...${NC}"
    
    # Wait for NTP to initialize
    echo -e "${BLUE}[*] Waiting for NTP to initialize (15 seconds)...${NC}"
    sleep 15
    
    # Check if NTP is listening
    echo -e "${BLUE}[*] Checking if NTP is listening on port 123:${NC}"
    if netstat -tulnp 2>/dev/null | grep -q ":123"; then
        echo -e "${GREEN}[+] NTP is listening on port 123${NC}"
        netstat -tulnp 2>/dev/null | grep ":123"
    else
        echo -e "${RED}[!] NTP is not listening on port 123${NC}"
        echo -e "${YELLOW}[*] Checking with ss command...${NC}"
        ss -ulnp | grep ":123"
    fi
    
    # Check NTP associations
    echo -e "${BLUE}[*] Checking NTP associations:${NC}"
    ntpq -p || echo -e "${RED}[!] ntpq command failed${NC}"
    
    # Check if mode 7 is enabled
    echo -e "${BLUE}[*] Testing if mode 7 is enabled:${NC}"
    if ntpq -c "rv 0" &> /dev/null; then
        echo -e "${GREEN}[+] Mode 7 is enabled${NC}"
    else
        echo -e "${RED}[!] Mode 7 does not appear to be enabled${NC}"
    fi
    
    # Start the vulnerability simulator
    echo -e "${BLUE}[*] Starting vulnerability simulator...${NC}"
    systemctl start ntp-vuln-sim
    
    # Check if simulator is running
    if systemctl is-active --quiet ntp-vuln-sim; then
        echo -e "${GREEN}[+] Vulnerability simulator started successfully${NC}"
    else
        echo -e "${RED}[!] Failed to start vulnerability simulator${NC}"
        systemctl status ntp-vuln-sim
    fi
    
    echo -e "${GREEN}[+] NTP server is now vulnerable to CVE-2016-9311${NC}"
}

# Function to configure firewall
configure_firewall() {
    echo -e "${BLUE}[*] Configuring firewall for NTP...${NC}"
    
    # Check if UFW is installed
    if command -v ufw &> /dev/null; then
        # Allow NTP traffic
        ufw allow 123/udp
        echo -e "${GREEN}[+] UFW rule added for NTP (UDP 123)${NC}"
    else
        echo -e "${YELLOW}[!] UFW not installed. Please manually configure your firewall to allow UDP port 123${NC}"
    fi
}

# Function to display setup information
display_setup_info() {
    # Get IP address
    IP_ADDR=$(hostname -I | awk '{print $1}')
    
    echo -e "\n${GREEN}=== NTP Vulnerable Server Setup Complete ===${NC}"
    echo -e "${YELLOW}Server IP: ${IP_ADDR}${NC}"
    echo -e "${YELLOW}NTP Port: 123/UDP${NC}"
    echo -e "${YELLOW}Vulnerability: CVE-2016-9311 (trap command)${NC}"
    
    echo -e "\n${BLUE}To test the vulnerability:${NC}"
    echo -e "  ntpq -c \"readvar 0 trap\" ${IP_ADDR}"
    
    echo -e "\n${BLUE}To test with the attack script:${NC}"
    echo -e "  sudo python3 ntp_kod.py --target ${IP_ADDR} --technique trap --intensity 10 --duration 60"
    
    echo -e "\n${BLUE}To check the vulnerability simulator logs:${NC}"
    echo -e "  journalctl -u ntp-vuln-sim -f"
    
    echo -e "\n${RED}SECURITY WARNING:${NC}"
    echo -e "${RED}This server is intentionally vulnerable. Do not expose it to untrusted networks.${NC}"
    echo -e "${RED}Use only for educational purposes in an isolated lab environment.${NC}"
    
    echo -e "\n${BLUE}To clean up after testing:${NC}"
    echo -e "  sudo $0 --cleanup"
}

# Function to clean up vulnerable NTP setup
cleanup_ntp() {
    echo -e "${BLUE}[*] Cleaning up vulnerable NTP setup...${NC}"
    
    # Stop and disable vulnerability simulator
    if systemctl is-active --quiet ntp-vuln-sim; then
        systemctl stop ntp-vuln-sim
        systemctl disable ntp-vuln-sim
        rm -f /etc/systemd/system/ntp-vuln-sim.service
        systemctl daemon-reload
        echo -e "${GREEN}[+] Stopped and removed vulnerability simulator${NC}"
    fi
    
    # Remove vulnerability script
    if [ -d /opt/ntp-vuln ]; then
        rm -rf /opt/ntp-vuln
        echo -e "${GREEN}[+] Removed vulnerability script${NC}"
    fi
    
    # Stop and disable NTP service
    if systemctl is-active --quiet ntp; then
        systemctl stop ntp
        systemctl disable ntp
        echo -e "${GREEN}[+] Stopped and disabled NTP service${NC}"
    fi
    
    # Remove NTP package
    apt-get remove --purge -y ntp ntpdate
    apt-get autoremove -y
    echo -e "${GREEN}[+] Removed NTP packages${NC}"
    
    # Restore original configuration if it exists
    if [ -f /root/ntp-backup/ntp.conf.bak ]; then
        echo -e "${BLUE}[*] Restoring original NTP configuration...${NC}"
        apt-get install -y ntp
        cp /root/ntp-backup/ntp.conf.bak /etc/ntp.conf
        
        if [ -f /root/ntp-backup/ntp.service.bak ]; then
            cp /root/ntp-backup/ntp.service.bak /etc/systemd/system/ntp.service
        fi
        
        systemctl daemon-reload
        systemctl enable ntp
        systemctl start ntp
        
        echo -e "${GREEN}[+] Original NTP configuration restored${NC}"
    fi
    
    echo -e "${GREEN}[+] Cleanup completed successfully${NC}"
}

# Main function
main() {
    display_banner
    check_root
    check_ubuntu
    
    # Check if cleanup mode is requested
    if [ "$1" == "--cleanup" ]; then
        cleanup_ntp
        exit 0
    fi
    
    # Confirm setup
    echo -e "${YELLOW}This script will set up an NTP server vulnerable to CVE-2016-9311.${NC}"
    echo -e "${YELLOW}This should ONLY be used in an isolated lab environment.${NC}"
    echo -e "${YELLOW}Continue? (y/n)${NC}"
    read -r confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Setup aborted.${NC}"
        exit 1
    fi
    
    # Perform setup
    backup_existing_config
    stop_existing_ntp
    setup_direct_ntp
    create_vulnerability_script
    configure_firewall
    verify_ntp_setup
    display_setup_info
}

# Run main function with all arguments
main "$@"
