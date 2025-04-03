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

# Function to set up vulnerable NTP using Docker
setup_docker_ntp() {
    echo -e "${BLUE}[*] Setting up vulnerable NTP using Docker...${NC}"
    
    # Create a directory for NTP configuration
    mkdir -p /etc/ntp-docker
    
    # Create vulnerable NTP configuration
    cat > /etc/ntp-docker/ntp.conf << 'EOF'
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

# Trap configuration (vulnerable to CVE-2016-9311)
trap 127.0.0.1 interface
trap 127.0.0.1.2 interface
trap 127.0.0.1.3 interface

# Log file
logfile /var/log/ntp.log
EOF
    
    # Create Dockerfile for vulnerable NTP
    cat > /etc/ntp-docker/Dockerfile << 'EOF'
FROM ubuntu:16.04

# Install NTP package first as a fallback
RUN apt-get update && \
    apt-get install -y ntp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Then try to build the vulnerable version from source
RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libcap-dev wget && \
    cd /tmp && \
    wget http://archive.ntp.org/ntp4/ntp-4.2/ntp-4.2.8p8.tar.gz && \
    tar -xzf ntp-4.2.8p8.tar.gz && \
    cd ntp-4.2.8p8 && \
    ./configure --prefix=/usr --enable-all-clocks --enable-parse-clocks && \
    make && \
    make install && \
    # Create necessary directories
    mkdir -p /var/lib/ntp /var/log/ntpstats && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

COPY ntp.conf /etc/ntp.conf

EXPOSE 123/udp

# Use the correct path to ntpd, with fallback options
CMD ["/bin/bash", "-c", "if [ -x /usr/sbin/ntpd ]; then /usr/sbin/ntpd -n -d -g; elif [ -x /usr/bin/ntpd ]; then /usr/bin/ntpd -n -d -g; else ntpd -n -d -g; fi"]
EOF
    
    # Build the Docker image
    echo -e "${BLUE}[*] Building Docker image for vulnerable NTP (this may take a few minutes)...${NC}"
    cd /etc/ntp-docker
    if ! docker build -t ntp-vulnerable .; then
        echo -e "${RED}[!] Failed to build Docker image${NC}"
        return 1
    fi
    
    # Stop any existing container
    docker stop ntp-vulnerable 2>/dev/null || true
    docker rm ntp-vulnerable 2>/dev/null || true
    
    # Run the container
    echo -e "${BLUE}[*] Starting vulnerable NTP container...${NC}"
    if ! docker run -d --name ntp-vulnerable --restart unless-stopped --net=host ntp-vulnerable; then
        echo -e "${RED}[!] Failed to start Docker container${NC}"
        
        # Debug information
        echo -e "${YELLOW}[*] Debug: Checking Docker container logs...${NC}"
        docker logs ntp-vulnerable
        
        # Try alternative approach with simpler image
        echo -e "${YELLOW}[*] Trying alternative approach with simpler Docker image...${NC}"
        
        # Create simpler Dockerfile
        cat > /etc/ntp-docker/Dockerfile.simple << 'EOF'
FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y ntp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY ntp.conf /etc/ntp.conf

EXPOSE 123/udp

CMD ["ntpd", "-n", "-d", "-g"]
EOF
        
        # Build the simpler Docker image
        if ! docker build -t ntp-vulnerable-simple -f Dockerfile.simple .; then
            echo -e "${RED}[!] Failed to build simple Docker image${NC}"
            return 1
        fi
        
        # Run the simpler container
        if ! docker run -d --name ntp-vulnerable --restart unless-stopped --net=host ntp-vulnerable-simple; then
            echo -e "${RED}[!] Failed to start simple Docker container${NC}"
            return 1
        fi
        
        echo -e "${GREEN}[+] Started NTP container with fallback image${NC}"
    fi
    
    # Create a systemd service to start the container on boot
    cat > /etc/systemd/system/ntp-docker.service << 'EOF'
[Unit]
Description=Vulnerable NTP Docker Container
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker start ntp-vulnerable
ExecStop=/usr/bin/docker stop ntp-vulnerable

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable the service
    systemctl daemon-reload
    systemctl enable ntp-docker
    
    echo -e "${GREEN}[+] Vulnerable NTP Docker container is running${NC}"
    return 0
}

# Function to verify NTP setup
verify_ntp_setup() {
    echo -e "${BLUE}[*] Verifying NTP setup...${NC}"
    
    # Wait for NTP to initialize
    echo -e "${BLUE}[*] Waiting for NTP to initialize (15 seconds)...${NC}"
    sleep 15
    
    # Check if Docker container is running
    echo -e "${BLUE}[*] Checking if Docker container is running:${NC}"
    if docker ps | grep -q ntp-vulnerable; then
        echo -e "${GREEN}[+] NTP Docker container is running${NC}"
        
        # Show container details
        echo -e "${BLUE}[*] Container details:${NC}"
        docker ps | grep ntp-vulnerable
    else
        echo -e "${RED}[!] NTP Docker container is not running${NC}"
        echo -e "${YELLOW}[*] Checking container status:${NC}"
        docker ps -a | grep ntp-vulnerable
        
        echo -e "${YELLOW}[*] Container logs:${NC}"
        docker logs ntp-vulnerable
    fi
    
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
    
    # Install ntpq for testing if not already installed
    if ! command -v ntpq &> /dev/null; then
        echo -e "${BLUE}[*] Installing ntpq for testing...${NC}"
        apt-get update
        apt-get install -y ntp-utils || apt-get install -y ntp
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
        
        # Try to set trap variables manually
        echo -e "${YELLOW}[*] Attempting to set trap variables manually...${NC}"
        ntpq -c "trap 127.0.0.1 interface" localhost
        sleep 2
        ntpq -c "readvar 0 trap" 2>/dev/null
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
    echo -e "${YELLOW}NTP Version: 4.2.8p8 (vulnerable to CVE-2016-9311)${NC}"
    echo -e "${YELLOW}Running in Docker: Yes${NC}"
    
    echo -e "\n${BLUE}To test the vulnerability:${NC}"
    echo -e "  ntpq -c \"readvar 0 trap\" ${IP_ADDR}"
    
    echo -e "\n${BLUE}To test with the attack script:${NC}"
    echo -e "  sudo python3 ntp_kod.py --target ${IP_ADDR} --technique trap --intensity 10 --duration 60"
    
    echo -e "\n${BLUE}To view Docker container logs:${NC}"
    echo -e "  docker logs ntp-vulnerable"
    
    echo -e "\n${RED}SECURITY WARNING:${NC}"
    echo -e "${RED}This server is intentionally vulnerable. Do not expose it to untrusted networks.${NC}"
    echo -e "${RED}Use only for educational purposes in an isolated lab environment.${NC}"
    
    echo -e "\n${BLUE}To clean up after testing:${NC}"
    echo -e "  sudo $0 --cleanup"
}

# Function to clean up vulnerable NTP setup
cleanup_ntp() {
    echo -e "${BLUE}[*] Cleaning up vulnerable NTP setup...${NC}"
    
    # Stop and remove Docker container if it exists
    if docker ps -a | grep -q ntp-vulnerable; then
        echo -e "${BLUE}[*] Stopping and removing Docker container...${NC}"
        docker stop ntp-vulnerable
        docker rm ntp-vulnerable
        echo -e "${GREEN}[+] Docker container removed${NC}"
    fi
    
    # Remove Docker images
    if docker images | grep -q ntp-vulnerable; then
        echo -e "${BLUE}[*] Removing Docker images...${NC}"
        docker rmi ntp-vulnerable ntp-vulnerable-simple 2>/dev/null || true
        echo -e "${GREEN}[+] Docker images removed${NC}"
    fi
    
    # Remove Docker service file
    if [ -f /etc/systemd/system/ntp-docker.service ]; then
        echo -e "${BLUE}[*] Removing Docker service file...${NC}"
        systemctl disable ntp-docker
        rm -f /etc/systemd/system/ntp-docker.service
        systemctl daemon-reload
        echo -e "${GREEN}[+] Docker service file removed${NC}"
    fi
    
    # Remove configuration files
    echo -e "${BLUE}[*] Removing configuration files...${NC}"
    rm -rf /etc/ntp-docker
    
    # Stop and disable NTP service if it exists
    if systemctl is-active --quiet ntp; then
        systemctl stop ntp
        systemctl disable ntp
    fi
    
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
    echo -e "${YELLOW}This script will set up an NTP server vulnerable to CVE-2016-9311 using Docker.${NC}"
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
    
    # Check if Docker is installed, install if not
    if ! check_docker; then
        if ! install_docker; then
            echo -e "${RED}[!] Failed to install Docker. Cannot continue.${NC}"
            exit 1
        fi
    fi
    
    # Set up vulnerable NTP using Docker
    if ! setup_docker_ntp; then
        echo -e "${RED}[!] Failed to set up vulnerable NTP using Docker.${NC}"
        exit 1
    fi
    
    configure_firewall
    verify_ntp_setup
    display_setup_info
}

# Run main function with all arguments
main "$@"
