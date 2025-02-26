import sys
import socket
import time
import threading
from art import *

# Validate input
def is_valid_ipv4(ip):
   try:
       socket.inet_aton(ip)
       parts = ip.split('.')
       return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
   except socket.error:
       return False

def scan_target(target):
   print("=" * 50)
   print(f"Scanning Target: {target}")
   print("=" * 50)
  
   found_open_port = False
   start_time = time.time()

   try:
       for port in range(1, 65535):
           s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           socket.setdefaulttimeout(1)
           result = s.connect_ex((target, port))
           if result == 0:
               print(f"> Port {port} is open on {target}")
               found_open_port = True
               break
           s.close()


           if time.time() - start_time > 5 and not found_open_port:
               print(f"No open ports found for {target}, Host Inactive.\nExiting Port Scanner for {target}...")
               return

   except socket.error:
       print(f"\nConnection Lost to {target}")
       return

# Get user inputs
tprint("\nPORT\nSCANNER", font="char1")
print("=" * 50)
target1 = input("Enter the first target IPv4 address: ")
target2 = input("Enter the second target IPv4 address: ")

# Validate inputs
if not is_valid_ipv4(target1) or not is_valid_ipv4(target2):
   print("Invalid IPv4 address")
   sys.exit()

# Threading to scan both targets simultaneously
thread1 = Thread(target=scan_target, args=(target1,))
thread2 = Thread(target=scan_target, args=(target2,))

# Start both threads
thread1.start()
thread2.start()

# Wait for both threads to complete
thread1.join()
thread2.join()

print("Scanning complete for both targets.")


