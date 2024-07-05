import os
import subprocess
import scapy.all as scapy
import nmap
import requests
import dns.resolver

# Function to perform ping
def ping(ip):
    response = os.system(f"ping -c 4 {ip}")
    if response == 0:
        print(f"{ip} is up")
    else:
        print(f"{ip} is down")

# Function to perform traceroute
def traceroute(ip):
    os.system(f"traceroute {ip}")

# Function to perform a comprehensive port scan
def port_scan(target, scan_type):
    scanner = nmap.PortScanner()
    scan_arguments = {
        'SYN': '-sS',
        'TCP': '-sT',
        'UDP': '-sU',
        'ACK': '-sA',
        'Comprehensive': '-sS -sU -sT -A -v'
    }
    print(f"Performing {scan_type} scan on {target}")
    scanner.scan(target, arguments=scan_arguments.get(scan_type, '-sS'))
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = scanner[host][proto].keys()
            for port in lport:
                service = scanner[host][proto][port]['name']
                state = scanner[host][proto][port]['state']
                print(f"Port: {port}\tState: {state}\tService: {service}")

# Function to enumerate network services and detect OS
def service_enumeration(target):
    scanner = nmap.PortScanner()
    print(f"Enumerating network services and detecting OS on {target}")
    try:
        if os.geteuid() != 0:
            print("This function requires root privileges. Please run the script with sudo.")
            return
        
        scanner.scan(target, arguments='-sV -O')
        for host in scanner.all_hosts():
            print(f"Host: {host} ({scanner[host].hostname()})")
            if 'osclass' in scanner[host]:
                for osclass in scanner[host]['osclass']:
                    print(f"OS Type: {osclass['type']}")
                    print(f"OS Vendor: {osclass['vendor']}")
                    print(f"OS Family: {osclass['osfamily']}")
                    print(f"OS Generation: {osclass['osgen']}")
                    print(f"OS Accuracy: {osclass['accuracy']}%")
            else:
                print("OS detection not available.")
            for proto in scanner[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = scanner[host][proto].keys()
                for port in lport:
                    state = scanner[host][proto][port]['state']
                    service = scanner[host][proto][port]['name']
                    product = scanner[host][proto][port].get('product', 'unknown')
                    version = scanner[host][proto][port].get('version', 'unknown')
                    print(f"Port: {port}\tState: {state}\tService: {service}\tProduct: {product}\tVersion: {version}")
    except nmap.PortScannerError as e:
        print(f"Error during service enumeration: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

# Function to perform host discovery on a local network
def host_discovery(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for elem in answered_list:
        print(f"IP: {elem[1].psrc} | MAC: {elem[1].hwsrc}")

# Function to detect MAC address of a given IP
def mac_address_detection(ip):
    response = scapy.arping(ip, verbose=False)[0]
    for _, rcv in response:
        print(f"IP: {rcv.psrc} | MAC: {rcv.hwsrc}")

# Function to perform subdomain enumeration
def subdomain_enumeration(domain):
    subdomains = ['www', 'mail', 'ftp', 'test', 'dev', 'webmail']
    print(f"Subdomains for {domain}:")
    for subdomain in subdomains:
        subdomain_url = f"{subdomain}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain_url)
            for rdata in answers:
                print(f"{subdomain_url} -> {rdata.address}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"{subdomain_url} does not exist")

# Function to perform vulnerability reconnaissance using Nmap
def vulnerability_reconnaissance(ip):
    scanner = nmap.PortScanner()
    print(f"Performing vulnerability scan on {ip}")
    try:
        scanner.scan(ip, arguments='-sV --script vuln')
        if ip in scanner.all_hosts():
            host = scanner[ip]
            print(f"Host: {host.hostname()} ({ip})")
            print(f"State: {host.state()}")

            for proto in host.all_protocols():
                lport = host[proto].keys()
                for port in lport:
                    service = host[proto][port].get('name', 'unknown')
                    product = host[proto][port].get('product', 'unknown')
                    version = host[proto][port].get('version', 'unknown')
                    state = host[proto][port]['state']

                    print(f"\nPort: {port}/{proto}")
                    print(f"  State: {state}")
                    print(f"  Service: {service}")
                    print(f"  Product: {product}")
                    print(f"  Version: {version}")

                    if 'script' in host[proto][port]:
                        print("  Vulnerabilities found:")
                        for script_name, script_output in host[proto][port]['script'].items():
                            print(f"    {script_name}:")
                            for line in script_output.split('\n'):
                                print(f"      {line}")
                    else:
                        print("  No vulnerabilities detected for this port.")
        else:
            print("No vulnerabilities found or Nmap scan failed.")
    except Exception as e:
        print(f"Error during vulnerability scanning: {e}")

# Function to perform directory busting
def directory_busting(url, wordlist):
    print(f"Checking directories on {url}:")
    try:
        with open(wordlist, 'r') as file:
            directories = file.read().splitlines()
            for directory in directories:
                full_url = f"{url}/{directory}"
                try:
                    response = requests.get(full_url)
                    if response.status_code == 200:
                        print(f"[+] {full_url} - Found")
                except requests.exceptions.RequestException as e:
                    print(f"Error checking {full_url}: {e}")
    except FileNotFoundError:
        print(f"Wordlist file '{wordlist}' not found.")

# Function to sniff network packets
def packet_sniffing(interface):
    print(f"Sniffing packets on interface: {interface}")
    try:
        def process_packet(packet):
            print("\n" + "-"*50)
            try:
                print(packet.show(dump=True))  # Display packet details

                # Check for specific packet layers and print information
                if packet.haslayer(scapy.IP):
                    print(f"[+] IP Packet from {packet[scapy.IP].src} to {packet[scapy.IP].dst}")
                if packet.haslayer(scapy.TCP):
                    print(f"[+] TCP Packet from {packet[scapy.IP].src}:{packet[scapy.TCP].sport} to {packet[scapy.IP].dst}:{packet[scapy.TCP].dport}")
                if packet.haslayer(scapy.UDP):
                    print(f"[+] UDP Packet from {packet[scapy.IP].src}:{packet[scapy.UDP].sport} to {packet[scapy.IP].dst}:{packet[scapy.UDP].dport}")

            except Exception as e:
                print(f"Error processing packet: {e}")

        scapy.sniff(iface=interface, prn=process_packet, store=False)
    except Exception as e:
        print(f"Error while sniffing packets: {e}")

# Function to display the menu and get user choice
def menu():
    print("\nNetwork Reconnaissance Tool")
    print("1. Ping a Host")
    print("2. Traceroute to a Host")
    print("3. Port Scan")
    print("4. Service Enumeration with OS Detection")
    print("5. Host Discovery")
    print("6. MAC Address Detection")
    print("7. Subdomain Enumeration")
    print("8. Vulnerability Reconnaissance")
    print("9. Directory Busting")
    print("10. Packet Sniffing")
    print("11. Exit")
    choice = int(input("Select an option (1-11): "))
    return choice

# Main function to run the tool
def main():
    while True:
        choice = menu()
        if choice == 1:
            ip = input("Enter the IP address to ping: ")
            ping(ip)
        elif choice == 2:
            ip = input("Enter the IP address to traceroute: ")
            traceroute(ip)
        elif choice == 3:
            target = input("Enter the IP address to scan: ")
            scan_type = input("Enter the type of scan (SYN/TCP/UDP/ACK/Comprehensive): ")
            port_scan(target, scan_type)
        elif choice == 4:
            target = input("Enter the IP address or domain to enumerate services and detect OS: ")
            service_enumeration(target)
        elif choice == 5:
            ip_range = input("Enter the IP range to discover hosts (e.g., 192.168.1.0/24): ")
            host_discovery(ip_range)
        elif choice == 6:
            ip = input("Enter the IP address to detect MAC address: ")
            mac_address_detection(ip)
        elif choice == 7:
            domain = input("Enter the domain to enumerate subdomains: ")
            subdomain_enumeration(domain)
        elif choice == 8:
            ip = input("Enter the IP address to perform vulnerability reconnaissance: ")
            vulnerability_reconnaissance(ip)
        elif choice == 9:
            url = input("Enter the URL to perform directory busting: ")
            wordlist = input("Enter the path to the wordlist: ")
            directory_busting(url, wordlist)
        elif choice == 10:
            interface = input("Enter the network interface to sniff packets on: ")
            packet_sniffing(interface)
        elif choice == 11:
            print("Exiting the tool.")
            break
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
