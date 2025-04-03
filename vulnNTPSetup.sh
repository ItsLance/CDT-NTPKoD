#!/bin/bash

# NTP Vulnerable Setup Script
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

# Function to check system requirements
check_system_requirements() {
    echo -e "${BLUE}[*] Checking system requirements...${NC}"
    
    # Check disk space
    FREE_SPACE=$(df -k / | awk 'NR==2 {print $4}')
    if [ "$FREE_SPACE" -lt 1000000 ]; then  # Less than ~1GB
        echo -e "${YELLOW}[!] Warning: Low disk space. Build process may fail.${NC}"
    fi
    
    # Check memory
    FREE_MEM=$(free -m | awk 'NR==2 {print $4}')
    if [ "$FREE_MEM" -lt 512 ]; then  # Less than 512MB
        echo -e "${YELLOW}[!] Warning: Low memory. Build process may be slow or fail.${NC}"
    fi
    
    # Check internet connectivity
    if ! ping -c 1 archive.ntp.org &> /dev/null; then
        echo -e "${YELLOW}[!] Warning: Cannot reach archive.ntp.org. Check internet connection.${NC}"
    fi
    
    echo -e "${GREEN}[+] System requirements checked${NC}"
}

# Function to install vulnerable NTP using package manager (preferred method)
install_ntp_package() {
    echo -e "${BLUE}[*] Installing NTP package...${NC}"
    
    # Remove existing NTP installation
    apt-get remove -y ntp ntpdate &> /dev/null
    
    # Install NTP package
    apt-get update
    if apt-get install -y ntp; then
        echo -e "${GREEN}[+] NTP package installed successfully${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Failed to install NTP package. Will try building from source.${NC}"
        return 1
    fi
}

# Function to install vulnerable NTP from source (fallback method)
install_vulnerable_ntp_source() {
    echo -e "${BLUE}[*] Installing vulnerable NTP from source...${NC}"
    
    # Install build dependencies
    echo -e "${BLUE}[*] Installing build dependencies...${NC}"
    apt-get update
    apt-get install -y build-essential libssl-dev libcap-dev
    
    # Create build directory
    BUILD_DIR=$(mktemp -d)
    cd "$BUILD_DIR" || { echo -e "${RED}[!] Failed to create build directory${NC}"; exit 1; }
    
    # Download vulnerable NTP version
    echo -e "${BLUE}[*] Downloading NTP 4.2.8p8 (vulnerable to CVE-2016-9311)...${NC}"
    if ! wget -q http://archive.ntp.org/ntp4/ntp-4.2/ntp-4.2.8p8.tar.gz; then
        echo -e "${RED}[!] Failed to download NTP source. Check your internet connection.${NC}"
        cd / || return 1
        rm -rf "$BUILD_DIR"
        return 1
    fi
    
    # Extract and build
    echo -e "${BLUE}[*] Extracting and building NTP...${NC}"
    if ! tar -xzf ntp-4.2.8p8.tar.gz; then
        echo -e "${RED}[!] Failed to extract NTP source.${NC}"
        cd / || return 1
        rm -rf "$BUILD_DIR"
        return 1
    fi
    
    cd ntp-4.2.8p8 || { echo -e "${RED}[!] Failed to enter source directory${NC}"; return 1; }
    
    # Configure with verbose output to help diagnose issues
    echo -e "${BLUE}[*] Configuring NTP build...${NC}"
    if ! ./configure --prefix=/usr --enable-all-clocks --enable-parse-clocks; then
        echo -e "${RED}[!] Configure failed. See output above for details.${NC}"
        cd / || return 1
        rm -rf "$BUILD_DIR"
        return 1
    fi
    
    # Build with verbose output
    echo -e "${BLUE}[*] Building NTP (this may take a while)...${NC}"
    if ! make -j"$(nproc)"; then
        echo -e "${RED}[!] Build failed. See output above for details.${NC}"
        cd / || return 1
        rm -rf "$BUILD_DIR"
        return 1
    fi
    
    # Install
    echo -e "${BLUE}[*] Installing NTP...${NC}"
    if ! make install; then
        echo -e "${RED}[!] Installation failed. See output above for details.${NC}"
        cd / || return 1
        rm -rf "$BUILD_DIR"
        return 1
    fi
    
    echo -e "${GREEN}[+] Vulnerable NTP version installed successfully from source${NC}"
    
    # Clean up build directory
    cd / || return 1
    rm -rf "$BUILD_DIR"
    return 0
}

# Function to create vulnerable NTP configuration
configure_vulnerable_ntp() {
    echo -e "${BLUE}[*] Creating vulnerable NTP configuration...${NC}"
    
    # Create NTP configuration file
    cat > /etc/ntp.conf << 'EOF'
# Basic NTP Configuration with vulnerable settings

# Default restrictions (allow everything for testing)
restrict default kod nomodify notrap nopeer

# Allow localhost full access
restrict 127.0.0.1
restrict ::1

# Server configuration - use public servers
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
    
    echo -e "${GREEN}[+] Created vulnerable NTP configuration${NC}"
    
    # Create necessary directories
    mkdir -p /var/lib/ntp
    mkdir -p /var/log/ntpstats
    touch /var/log/ntp.log
    
    # Create NTP user if it doesn't exist
    if ! id -u ntp &>/dev/null; then
        useradd -r -M -s /sbin/nologin ntp
    fi
    
    # Set proper permissions
    chown -R ntp:ntp /var/lib/ntp
    chown -R ntp:ntp /var/log/ntpstats
    chown ntp:ntp /var/log/ntp.log
    
    # Check if systemd service file already exists
    if [ ! -f /lib/systemd/system/ntp.service ] && [ ! -f /etc/systemd/system/ntp.service ]; then
        # Create systemd service file
        cat > /etc/systemd/system/ntp.service << 'EOF'
[Unit]
Description=Network Time Protocol daemon
Documentation=man:ntpd(8)
After=network.target

[Service]
Type=forking
ExecStart=/usr/sbin/ntpd -u ntp:ntp -g
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        echo -e "${GREEN}[+] Created NTP service file${NC}"
    else
        echo -e "${GREEN}[+] Using existing NTP service file${NC}"
    fi
    
    # Reload systemd
    systemctl daemon-reload
}

# Function to start NTP service
start_ntp_service() {
    echo -e "${BLUE}[*] Starting vulnerable NTP service...${NC}"
    
    # Enable and start NTP service
    systemctl enable ntp &> /dev/null
    systemctl restart ntp
    
    # Wait a moment for the service to start
    sleep 3
    
    # Check if service is running
    if systemctl is-active --quiet ntp; then
        echo -e "${GREEN}[+] NTP service started successfully${NC}"
    else
        echo -e "${RED}[!] Failed to start NTP service${NC}"
        echo -e "${YELLOW}[*] Checking NTP service status...${NC}"
        systemctl status ntp
        echo -e "${YELLOW}[*] Check logs with: journalctl -u ntp${NC}"
    fi
}

# Function to verify NTP configuration
verify_ntp_setup() {
    echo -e "${BLUE}[*] Verifying NTP setup...${NC}"
    
    # Check if NTP is listening
    if netstat -tulnp 2>/dev/null | grep -q ":123"; then
        echo -e "${GREEN}[+] NTP is listening on port 123${NC}"
    else
        echo -e "${RED}[!] NTP is not listening on port 123${NC}"
        echo -e "${YELLOW}[*] Checking with ss command...${NC}"
        ss -ulnp | grep ":123"
    fi
    
    # Wait for NTP to initialize
    echo -e "${BLUE}[*] Waiting for NTP to initialize (10 seconds)...${NC}"
    sleep 10
    
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
    echo -e "${YELLOW}Vulnerable to: CVE-2016-9311${NC}"
    
    echo -e "\n${BLUE}To test the vulnerability:${NC}"
    echo -e "  ntpq -c \"readvar 0 trap\" ${IP_ADDR}"
    
    echo -e "\n${RED}SECURITY WARNING:${NC}"
    echo -e "${RED}This server is intentionally vulnerable. Do not expose it to untrusted networks.${NC}"
    echo -e "${RED}Use only for educational purposes in an isolated lab environment.${NC}"
    
    echo -e "\n${BLUE}To clean up after testing:${NC}"
    echo -e "  sudo $0 --cleanup"
}

# Function to clean up vulnerable NTP setup
cleanup_ntp() {
    echo -e "${BLUE}[*] Cleaning up vulnerable NTP setup...${NC}"
    
    # Stop and disable NTP service
    systemctl stop ntp
    systemctl disable ntp
    
    # Remove vulnerable NTP installation
    echo -e "${BLUE}[*] Removing NTP installation...${NC}"
    apt-get remove --purge -y ntp ntpdate
    apt-get autoremove -y
    
    # Remove configuration files
    rm -f /etc/ntp.conf
    rm -f /etc/systemd/system/ntp.service
    
    # Clean up log files
    rm -f /var/log/ntp.log
    
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
    check_system_requirements
    
    # Try installing from package first, fall back to source if needed
    if ! install_ntp_package; then
        echo -e "${YELLOW}[!] Package installation failed, trying to build from source...${NC}"
        if ! install_vulnerable_ntp_source; then
            echo -e "${RED}[!] Both package and source installation methods failed.${NC}"
            echo -e "${RED}[!] Please check the error messages above and try to resolve the issues.${NC}"
            exit 1
        fi
    fi
    
    configure_vulnerable_ntp
    start_ntp_service
    configure_firewall
    verify_ntp_setup
    display_setup_info
}

# Run main function with all arguments
main "$@"
