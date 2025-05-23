# CDT-NTPKoD

# NTP Kiss-of-Death (KoD) Attack Tool

A comprehensive demonstration tool for various NTP server vulnerabilities through KoD (Kiss-of-Death) attack techniques. This tool is designed for educational purposes and authorized cybersecurity competitions only.

## ⚠️ Legal Disclaimer

**This tool is provided for EDUCATIONAL PURPOSES ONLY** to demonstrate potential vulnerabilities in NTP implementations. Using this tool against any targets without EXPLICIT AUTHORIZATION is ILLEGAL.

Use only in:
- Authorized cybersecurity competitions
- Controlled lab environments with explicit permission
- Pentesting engagements with proper authorization

The author accepts no liability for misuse or damage caused by this tool.

## Overview

This script demonstrates several techniques that could potentially crash or impair vulnerable NTP server implementations:

- **Malformed Packets**: Sending invalidly formatted NTP packets to trigger implementation bugs
- **Rate Limiting**: Overwhelming the server with many valid-looking requests
- **Large Packets**: Sending oversized NTP packets that some implementations may handle incorrectly
- **Fragmented Headers**: Using unusual header combinations that might trigger edge cases
- **Restriction Triggering**: Crafting packets to potentially trigger rate limiting mechanisms
- **Amplification Attacks**: Targeting mode 7 commands that may cause amplified responses
- **Mode 6 Exploitation**: Targeting control message vulnerabilities
- **CVE-2016-9311 Exploitation**: Specifically targeting the 'trap' variable information disclosure
- **IP Spoofing**: Randomizing source IP addresses to evade detection and rate limiting

## Dependencies

The script requires:

- Python 3.6+
- Scapy library

### Installation

```bash
Install Python dependencies
pip install scapy
```

```bash
On Linux, you may need additional permissions for packet crafting
sudo apt-get install libpcap-dev # For Debian/Ubuntu
```

## Usage

Basic syntax:

```bash
sudo python3 ntp-kod-attack.py --target TARGET_IP [options]
```

Root/administrator privileges are required for raw packet manipulation with Scapy.

### Command-line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Target NTP server IP address | (Required) |
| `--port` | Target NTP port | 123 |
| `--threads` | Number of threads to use | 8 |
| `--duration` | Attack duration in seconds | 60 |
| `--technique` | Attack technique to use (all, malformed, rate, large, fragment, restrict, amplification, mode6, mode7, cve-2016-9311) | all |
| `--intensity` | Attack intensity level (1-10) | 8 |
| `--spoof` | Enable IP spoofing | False |
| `--flood` | Enable aggressive flooding mode | False |
| `--analyze` | Run analysis on target before attack | False |

### Example Commands

```bash
Basic attack using all techniques:
sudo python3 ntp-kod-attack.py --target 192.168.1.10

Analyze target first, then attack using detected vulnerabilities:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --analyze

Focused attack using only malformed packets with high intensity:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --technique malformed --intensity 10 --duration 60

Attack with IP spoofing enabled:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --spoof --intensity 7

Maximum aggressive attack with flooding:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --spoof --flood --threads 16

Target specific CVE:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --technique cve-2016-9311

Low-intensity testing with fewer threads:
sudo python3 ntp-kod-attack.py --target 192.168.1.10 --threads 2 --intensity 3 --duration 15
```

## General Workflow

1. **Script Initialization**:
   - Parses command-line arguments
   - Displays banner and disclaimer
   - Validates target IP and checks for root privileges
   - Requests explicit confirmation to proceed

2. **Target Analysis** (if enabled):
   - Probes target to identify NTP version and implementation
   - Tests for specific vulnerabilities (mode6, mode7, monlist, CVE-2016-9311)
   - Adapts attack strategy based on detected vulnerabilities

3. **Attack Execution**:
   - Creates threads based on specified parameters
   - Each thread generates packets according to the selected technique
   - Packets are sent at a rate determined by the intensity level
   - Random timing jitter is applied to evade pattern detection
   - A monitoring thread checks if the target NTP service remains responsive

4. **Monitoring and Feedback**:
   - Real-time reporting on packets sent per thread
   - NTP service availability monitoring with response time tracking
   - Detection of service degradation
   - Color-coded console output for easy status tracking

5. **Termination**:
   - Runs for the specified duration or until interrupted
   - Gracefully stops all threads and reports final status

## Setting Up a Testing Environment

For safe and legal testing, set up a controlled lab environment:

### Option 1: Virtual Machine Setup

1. Create two VMs on the same isolated virtual network:
   - Attacker VM: Linux with Python and Scapy installed
   - Target VM: Running NTP server software (e.g., ntpd, chrony)

2. Configure the NTP server on the target VM:
   ```bash
   # For Ubuntu/Debian:
   sudo apt-get install ntp
   sudo systemctl start ntp
   ```

3. Verify the NTP server is listening:
   ```bash
   sudo netstat -tulnp | grep 123
   ```

4. From the attacker VM, run the tool against the target VM IP.

### Option 2: Docker-based Environment

1. Create a docker network:
   ```bash
   docker network create ntp-test-network
   ```

2. Run an NTP server container:
   ```bash
   docker run --name ntp-server --network ntp-test-network -d cturra/ntp
   ```

3. Run an attacker container with the script:
   ```bash
   docker run --name attacker --network ntp-test-network -it ubuntu:latest # Then install dependencies and run the script
   ```

## Monitoring the Effects

To observe the effects of the attack:

- On the target server, monitor system logs: `tail -f /var/log/syslog`
- Watch NTP server process: `top -p $(pgrep ntpd)`
- Check NTP service status: `ntpq -p`
- Monitor network traffic: `tcpdump -i any udp port 123 -vv`

## Advanced Features

### Target Analysis

   The --analyze option enables:

   - Automatic detection of NTP server version and implementation
   - Probing for specific vulnerabilities
   - Adaptation of attack techniques based on findings
   - More efficient targeting of known weaknesses
   
### IP Spoofing
   - The --spoof option enables source IP address randomization to:

### Evade rate limiting based on source IP
   - Make the attack harder to trace
   - Potentially bypass simple firewall rules
   - **Note:** IP spoofing requires root privileges and may not work on all networks due to egress filtering.

### Flood Mode
   The --flood option enables:

   - Maximum packet transmission rate
   - Minimal delays between packets
   - Higher burst sizes
   - More aggressive resource consumption
   - Warning: This can consume significant bandwidth and system resources.

### Timing Randomization
   The script implements:
   
   - Variable delays between packet bursts
   - Randomized packet timing within bursts
   - Jitter in the overall packet rate

   These features help evade detection systems that look for regular traffic patterns.

## Responsible Use

- Always obtain proper authorization before testing
- Document your testing activities
- Report vulnerabilities responsibly to software vendors
- Use minimum necessary intensity for educational purposes

## Troubleshooting

- Permission errors: Ensure you're running the script with root/administrator privileges
- Scapy issues: Check Scapy installation and dependencies
- Firewall blocking: Verify firewall rules allow UDP traffic on port 123
- IP spoofing not working: Some networks implement egress filtering that prevents spoofed packets
- Performance issues: Reduce intensity or number of threads if your system is overwhelmed

## Version History

- v1.0: Initial release with basic KoD techniques
- v1.1: Added IP spoofing, amplification attacks, and timing randomization
- v2.0: Major update with target analysis, vulnerability detection, adaptive attacks, and specialized exploits
