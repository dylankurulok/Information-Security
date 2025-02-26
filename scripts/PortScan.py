import sys
import socket
import time
import threading

# Function to validate if the given string is a valid IPv4 address
def is_valid_ipv4(ip):
   try:
       socket.inet_aton(ip)  # Check if the IP is valid
       parts = ip.split('.')
       return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)  # Ensure each part is in range
   except socket.error:
       return False

# Function to scan the target for open ports
def scan_target(target):
   print("=" * 50)
   print(f"Scanning Target: {target}")
   print("=" * 50)
  
   found_open_port = False  # Flag to track if any open port is found
   start_time = time.time()  # Record the start time of scanning

   try:
       for port in range(1, 65535):  # Iterate through all possible ports (1-65535)
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
           socket.setdefaulttimeout(1)  # Set timeout for the connection attempt
           result = s.connect_ex((target, port))  # Try connecting to the port

           if result == 0:
               print(f"> Port {port} is open on {target}")  # Print if port is open
               found_open_port = True
               break  # Stop scanning if an open port is found

           s.close()  # Close the socket connection

           # If no open ports are found within 5 seconds, assume host is inactive
           if time.time() - start_time > 5 and not found_open_port:
               print(f"No open ports found for {target}, Host Inactive.\nExiting Port Scanner for {target}...")
               return

   except socket.error:
       print(f"\nConnection Lost to {target}")  # Handle potential connection errors
       return

# Display a simple banner
print("=" * 50)
print("PORT SCANNER")
print("=" * 50)

# Prompt user for two target IP addresses
target1 = input("Enter the first target IPv4 address: ")
target2 = input("Enter the second target IPv4 address: ")

# Validate user inputs
if not is_valid_ipv4(target1) or not is_valid_ipv4(target2):
   print("Invalid IPv4 address")  # Notify user if input is not a valid IPv4
   sys.exit()

# Create threads to scan both targets simultaneously
thread1 = threading.Thread(target=scan_target, args=(target1,))
thread2 = threading.Thread(target=scan_target, args=(target2,))

# Start both threads
thread1.start()
thread2.start()

# Wait for both threads to complete before proceeding
thread1.join()
thread2.join()

print("Scanning complete for both targets.")
