#!/bin/bash

# NTP Vulnerability Setup Script
# This script installs a vulnerable version of NTP and configures it for CVE-2016-9311.
# This is intended to be a proof-of-concept of executing the red team tool.
# However, this is NOT viable in the current testing environment with the current Incus images
# From multiple iterations of this script to using things like Docker,
# there are no deprecated versions of ntp I can find in the given time I had with this assignment locally.
# It seems to be external. Nonetheless, I leave this script here for documentation and reference for future scripts if desired.

# This is meant to be run on the target machine as the vulnerable NTP "server"
# However, installing NTP and starting the service would just suffice for demonstration. 

# WARNING: For educational purposes in isolated lab environments only

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
    echo -e "${RED}THIS CODE CURRENTLY DOES NOT WORK${NC}"
    echo ""
}

# Function to check if script is run as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Function to detect Ubuntu version
detect_ubuntu_version() {
    if [ -f /etc/lsb-release ]; then
        source /etc/lsb-release
        UBUNTU_VERSION=$DISTRIB_RELEASE
        echo -e "${BLUE}[*] Detected Ubuntu ${UBUNTU_VERSION}${NC}"
        return 0
    else
        echo -e "${RED}[!] This script is designed for Ubuntu. Your system may not be compatible.${NC}"
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
        echo -e "${GREEN}[+] Stopped NTP service${NC}"
    elif systemctl is-active --quiet ntpd; then
        systemctl stop ntpd
        echo -e "${GREEN}[+] Stopped NTPD service${NC}"
    else
        echo -e "${YELLOW}[*] No active NTP service found${NC}"
    fi
    
    # Kill any remaining NTP processes
    if pgrep ntpd > /dev/null; then
        pkill ntpd
        echo -e "${GREEN}[+] Killed remaining NTP processes${NC}"
    fi
}

# Function to install vulnerable NTP version
install_vulnerable_ntp() {
    echo -e "${BLUE}[*] Installing vulnerable NTP version...${NC}"
    
    # Determine appropriate NTP version based on Ubuntu version
    case $UBUNTU_VERSION in
        18.04)
            NTP_VERSION="1:4.2.8p10+dfsg-5ubuntu7"
            ;;
        20.04)
            NTP_VERSION="1:4.2.8p12+dfsg-3ubuntu4"
            ;;
        22.04)
            NTP_VERSION="1:4.2.8p15+dfsg-1ubuntu1"
            ;;
        *)
            # For other versions, try the latest available
            NTP_VERSION=""
            echo -e "${YELLOW}[!] No specific vulnerable version known for Ubuntu ${UBUNTU_VERSION}${NC}"
            echo -e "${YELLOW}[!] Installing latest available version${NC}"
            ;;
    esac
    
    # Update package lists
    apt-get update
    
    # Install NTP with specific version if available
    if [ -n "$NTP_VERSION" ]; then
        echo -e "${BLUE}[*] Installing NTP version ${NTP_VERSION}${NC}"
        apt-get install -y ntp=$NTP_VERSION || apt-get install -y ntp
    else
        echo -e "${BLUE}[*] Installing latest NTP version${NC}"
        apt-get install -y ntp
    fi
    
    # Check if NTP was installed successfully
    if command -v ntpd &> /dev/null; then
        NTP_INSTALLED_VERSION=$(ntpd --version 2>&1 | head -n 1)
        echo -e "${GREEN}[+] Installed NTP version: ${NTP_INSTALLED_VERSION}${NC}"
    else
        echo -e "${RED}[!] Failed to install NTP${NC}"
        exit 1
    fi
}

# Function to configure NTP to be vulnerable
configure_vulnerable_ntp() {
    echo -e "${BLUE}[*] Configuring NTP to be vulnerable...${NC}"
    
    # Create vulnerable NTP configuration
    cat > /etc/ntp.conf << 'EOF'
# Basic NTP Configuration with vulnerable settings

# Default restrictions (allow everything for testing)
restrict default kod nomodify notrap nopeer

# Allow localhost full access
restrict 127.0.0.1
restrict ::1

# Server configuration
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

# Trap configuration (vulnerable to CVE-2016-9311)
trap 127.0.0.1 interface
trap 127.0.0.1.2 interface
trap 127.0.0.1.3 interface

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
    
    echo -e "${GREEN}[+] NTP configured with vulnerable settings${NC}"
}

# Function to start NTP service
start_ntp_service() {
    echo -e "${BLUE}[*] Starting NTP service...${NC}"
    
    # Restart NTP service
    systemctl restart ntp
    
    # Check if service is running
    if systemctl is-active --quiet ntp; then
        echo -e "${GREEN}[+] NTP service started successfully${NC}"
    else
        echo -e "${RED}[!] Failed to start NTP service${NC}"
        echo -e "${YELLOW}[*] Checking NTP service status...${NC}"
        systemctl status ntp
    fi
}

# Function to verify NTP configuration
verify_ntp_setup() {
    echo -e "${BLUE}[*] Verifying NTP setup...${NC}"
    
    # Wait for NTP to initialize
    echo -e "${BLUE}[*] Waiting for NTP to initialize (10 seconds)...${NC}"
    sleep 10
    
    # Check if NTP is listening
    echo -e "${BLUE}[*] Checking if NTP is listening on port 123:${NC}"
    if netstat -tulnp 2>/dev/null | grep -q ":123"; then
        echo -e "${GREEN}[+] NTP is listening on port 123${NC}"
    else
        echo -e "${RED}[!] NTP is not listening on port 123${NC}"
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
    
    # Test for CVE-2016-9311 vulnerability
    echo -e "${BLUE}[*] Testing for CVE-2016-9311 vulnerability...${NC}"
    if ntpq -c "readvar 0 trap" 2>/dev/null | grep -q "trap="; then
        echo -e "${GREEN}[+] Server appears to be vulnerable to CVE-2016-9311${NC}"
    else
        echo -e "${RED}[!] Server does not appear to be vulnerable to CVE-2016-9311${NC}"
        echo -e "${YELLOW}[*] This may be because the trap variables are not set or the server is not fully initialized${NC}"
    fi
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
    
    echo -e "\n${RED}SECURITY WARNING:${NC}"
    echo -e "${RED}This server is intentionally vulnerable. Do not expose it to untrusted networks.${NC}"
    echo -e "${RED}Use only for educational purposes in an isolated lab environment.${NC}"
    
    echo -e "\n${BLUE}To clean up after testing:${NC}"
    echo -e "  sudo $0 --cleanup"
}

# Function to clean up vulnerable NTP setup
cleanup_ntp() {
    echo -e "${BLUE}[*] Cleaning up vulnerable NTP setup...${NC}"
    
    # Stop NTP service
    systemctl stop ntp
    
    # Remove NTP package
    apt-get remove --purge -y ntp
    apt-get autoremove -y
    
    # Remove configuration files
    rm -f /etc/ntp.conf
    
    # Remove log files
    rm -f /var/log/ntp.log
    
    # Restore original configuration if it exists
    if [ -f /root/ntp-backup/ntp.conf.bak ]; then
        echo -e "${BLUE}[*] Restoring original NTP configuration...${NC}"
        apt-get install -y ntp
        cp /root/ntp-backup/ntp.conf.bak /etc/ntp.conf
        systemctl restart ntp
        echo -e "${GREEN}[+] Original NTP configuration restored${NC}"
    fi
    
    echo -e "${GREEN}[+] Cleanup completed successfully${NC}"
}

# Main function
main() {
    display_banner
    check_root
    
    # Check if cleanup mode is requested
    if [ "$1" == "--cleanup" ]; then
        cleanup_ntp
        exit 0
    fi
    
    # Detect Ubuntu version
    detect_ubuntu_version
    
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
    install_vulnerable_ntp
    configure_vulnerable_ntp
    start_ntp_service
    configure_firewall
    verify_ntp_setup
    display_setup_info
}

# Run main function with all arguments
main "$@"
