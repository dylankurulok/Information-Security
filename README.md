# Information Systems Security Projects

This repository contains various scripts and tools developed as part of my InfoSec coursework. The projects here cover a range of cybersecurity topics, including network monitoring, intrusion detection, packet analysis, and attack simulations.

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Projects](#projects)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Overview
The `network-security` repository includes Python scripts and other resources related to network security. These tools are designed to analyze network traffic, detect vulnerabilities, and simulate various attack techniques for educational and research purposes.

## Installation
To use the scripts in this repository, ensure you have the required dependencies installed. Most scripts rely on Python and third-party libraries such as `scapy` for packet manipulation.

### Prerequisites
- Python 3.x
- Scapy (`pip install scapy`)
- Other dependencies as specified in individual scripts

### Cloning the Repository
```sh
git clone https://github.com/yourusername/network-security.git
cd network-security
```

## Projects
### 1. Intrusion Detection System (IDS)
- Monitors network traffic for suspicious activity
- Extracts and logs information from various protocols (ICMP, ARP, HTTP, FTP, SSH)
- Generates alerts for potential threats
  ### 1.1 Packet Sniffer
  - Captures and logs network packets in real time
  - Extracts key details such as source/destination IP and protocol type

### 2. Port Scanner
- Scans target hosts for open ports
- Supports IPv4 address validation
- Detects inactive hosts and terminates after a timeout

### 3. ARP Spoofing Tool
- Simulates ARP poisoning attacks
- Redirects traffic for network analysis

## Usage
Each script includes a brief description and usage instructions within its source code. To run a specific script, navigate to its directory and execute it with Python:
```sh
python script_name.py
```
Some scripts may require administrative privileges to run properly.

## Contributing
Contributions are welcome! If you have improvements or additional security tools to add, feel free to fork the repository and submit a pull request.

## License
This project is for educational purposes only. Use responsibly.
