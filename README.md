# network-reconnaissance-tool
"A comprehensive network reconnaissance tool featuring ping, traceroute, port scanning, host discovery, MAC address detection, subdomain enumeration, vulnerability reconnaissance, network service enumeration, directory busting, and packet sniffing, complete with documentation and dependencies."
## Overview
The Network Reconnaissance Tool is a comprehensive utility that facilitates various network exploration and security assessment tasks. It offers a range of functionalities including ping, traceroute, port scanning, host discovery, MAC address detection, subdomain enumeration, vulnerability reconnaissance, directory busting, packet sniffing, and network service enumeration.
This tool is ideal for cybersecurity professionals, network administrators, and anyone interested in understanding and securing network environments.
## Features:
    Ping a Host: Check if a host is reachable.
    Traceroute to a Host: Track the route packets take to a destination.
    Port Scanning: Perform different types of port scans to identify open ports.
    Host Discovery: Identify active hosts on a network.
    MAC Address Detection: Find the MAC address of devices.
    Subdomain Enumeration: Discover subdomains of a given domain.
    Vulnerability Reconnaissance: Scan for known vulnerabilities.
    Directory Busting: Check for existing directories on a web server.
    Packet Sniffing: Capture and analyze network packets.
    Network Service Enumeration: Identify and detail services running on a host.
## Installation:
 ```sh
git clone https://github.com/saimarshad1/network-reconnaissance-tool.git
cd network-reconnaissance-tool
``` 
## Install Dependencies:
    scapy
    python-nmap
    requests
    dnspython
## Run the Tool:
    python3 main.py
## Usage: (Once installed, the tool can be run directly from the command line. Users are presented with a menu to select the desired operation:)
    Run the Tool:
        python tool.py
    Follow the On-Screen Menu: 
        Enter the number corresponding to the task you want to perform.
    Provide Input: 
        Enter required information like IP addresses or domains when prompted.
## Menu Options:
    1. Ping a Host: Checks if a host is reachable.
    2. Traceroute to a Host: Shows the path packets take to a target.
    3. Port Scan: Scans a target for open ports.
    Options: SYN, TCP, UDP, ACK, Comprehensive.
    4. Host Discovery: Lists active devices on a specified network.
    5. MAC Address Detection: Finds the MAC address of a device.
    6. Subdomain Enumeration: Lists subdomains for a given domain.
    7. Vulnerability Reconnaissance: Scans for vulnerabilities on a host.
    8. Directory Busting: Finds hidden directories on a web server.
    9. Packet Sniffing: Captures and displays network packets.
    10. Network Service Enumeration: Lists services running on a target.

    


