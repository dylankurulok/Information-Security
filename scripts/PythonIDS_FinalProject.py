import sys
from datetime import datetime
from scapy.all import *
import threading
import queue
from plyer import notification
import getpass

# Thread-safe queue for logging messages 
log_queue = queue.Queue()

# User authentication function
# Ensures that only authorized users can start the IDS
# Uses pre-defined credentials for simplicity
# Exits if authentication fails

def authenticate_user():
    print("User Authentication Required")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    
    correct_username = "admin"
    correct_password = "password"
    
    if username == correct_username and password == correct_password:
        print("Authentication successful!")
    else:
        print("Authentication failed! Exiting...")
        sys.exit(1)

# Alert system for real-time notifications and logging
class AlertSystem:
    def __init__(self, alert_log="alerts.log"):
        self.alert_log = alert_log

    def send_alert(self, message):
        print(f"ALERT: {message}")
        self.log_alert(message)
        self.show_os_notification(message)

    def log_alert(self, message):
        with open(self.alert_log, "a") as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

    def show_os_notification(self, message):
        notification.notify(
            title="Network Alert",
            message=message,
            timeout=5
        )

# Handles the processing of captured packets
# Runs as a separate thread to efficiently process network traffic
class PacketHandler(threading.Thread):
    def __init__(self, alert_system, gateway_ip, iface):
        super().__init__()
        self.alert_system = alert_system
        self.gateway_ip = gateway_ip
        self.iface = iface
        self.ssh_activity = {}  # Tracks SSH connection attempts per IP
        self.arp_table = {}  # Stores MAC addresses for ARP spoofing detection

    # Starts packet sniffing on the specified interface
    def run(self):
        sniff(
            iface=self.iface,
            store=0,
            prn=self.handle_packet,
            filter="icmp or tcp or udp or arp"
        )

    # Processes each captured packet and checks for suspicious activity
    def handle_packet(self, packet):
        is_suspicious = False  # Flag to indicate if a packet is suspicious

        # Check for ICMP packets
        if packet.haslayer(ICMP):
            message = f"ICMP Packet: {packet[IP].src} -> {packet[IP].dst} on {self.iface}"
            self.alert_system.send_alert(message)
            self.log_packet("ICMP", packet)  # <--- Calls the missing method

        # Detect ARP spoofing by checking for conflicting MAC addresses
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP Reply
                src_ip = packet[ARP].psrc
                src_mac = packet[ARP].hwsrc
                if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                    message = f"[!] ARP Spoofing Detected: {src_ip} is now linked to {src_mac} instead of {self.arp_table[src_ip]} on {self.iface}"
                    self.alert_system.send_alert(message)
                    self.log_packet("ARP_Spoofing", packet)
                self.arp_table[src_ip] = src_mac

        # Detect insecure protocols like HTTP
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            message = f"[!] Insecure Protocol Detected: HTTP from {packet[IP].src} -> {packet[IP].dst} on {self.iface}"
            self.alert_system.send_alert(message)
            self.log_packet("HTTP", packet)

        # Detect FTP traffic on ports 20 and 21
        if packet.haslayer(TCP) and (packet[TCP].dport in [20, 21] or packet[TCP].sport in [20, 21]):
            message = f"[!] Insecure Protocol Detected: FTP from {packet[IP].src} -> {packet[IP].dst} on {self.iface}"
            self.alert_system.send_alert(message)
            self.log_packet("FTP", packet)

        # Monitor DNS traffic for spoofing
        if packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53):
            if packet.haslayer(DNS):
                try:
                    if packet[DNS].qr == 1:  # Check if it's a DNS response
                        dns_answer = packet[DNS].an
                        if dns_answer and self.detect_dns_spoofing(dns_answer):
                            message = f"[!] DNS Spoofing Detected: Unexpected DNS response on {self.iface}"
                            self.alert_system.send_alert(message)
                            self.log_packet("DNS_Spoofing", packet)
                except AttributeError:
                    pass

        # Monitor SSH traffic for brute-force attempts
        if packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
            if self.detect_ssh_activity(packet):
                is_suspicious = True
            message = f"[!] SSH Traffic: {packet[IP].src} -> {packet[IP].dst} on {self.iface}"
            self.alert_system.send_alert(message)
            self.log_packet("SSH", packet)

        # Log suspicious packets
        if is_suspicious:
            self.log_packet("Suspicious", packet)

    # ** Add this missing method here **
    def log_packet(self, packet_type, packet):
        log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {packet_type}: {packet.summary()}\n"
        log_queue.put(log_entry)  # Add log entry to the queue for thread-safe logging

    # Detects potential SSH brute-force attempts
    def detect_ssh_activity(self, packet):
        src_ip = packet[IP].src
        if src_ip not in self.ssh_activity:
            self.ssh_activity[src_ip] = 0
        self.ssh_activity[src_ip] += 1
        if self.ssh_activity[src_ip] > 10:  # Alert if more than 10 SSH attempts
            message = f"[!] Potential SSH Brute Force Detected: {src_ip} with {self.ssh_activity[src_ip]} attempts"
            self.alert_system.send_alert(message)
            return True
        return False

# Entry point for the script
if __name__ == "__main__":
    authenticate_user()

    if len(sys.argv) < 3:
        print("Usage: python master_IDS.py <interface> <gateway_ip>")
        sys.exit(1)

    iface = sys.argv[1]
    gateway_ip = sys.argv[2]

    monitor = PacketHandler(AlertSystem(), gateway_ip, iface)
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        log_queue.put(None)
