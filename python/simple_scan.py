import ipaddress
import re
from scapy.all import IP, TCP, sr1, arping

def validate_ip_range(ip_range):
    """Validate and parse the IP range."""
    try:
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            ipaddress.ip_address(start_ip)
            ipaddress.ip_address(end_ip)
            return [str(ip) for ip in ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip))]
        elif '/' in ip_range:
            return [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
        else:
            ipaddress.ip_address(ip_range)  # Validate single IP
            return [ip_range]
    except ValueError:
        print("Invalid IP address or range format. Use CIDR (10.0.0.1/24), range (10.0.0.1-10.0.0.255), or a single IP.")
        return None
# use TCP SYN Scan (flags="S") on common port to scan for host response and port open
def tcp_scan(ip_list):
    """Perform TCP scan for common ports on given IPs."""
    hostip=[]

    common_ports = [22, 80, 443]
    for ip in ip_list:
        for port in common_ports:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:#(bi make it a little faster)
                print(f"Host {ip} - Port {port}: Open")
                hostip.append(f"{ip}-port {port} is open")
            else:
                print(f"-")
    print(hostip)# print host and port open
   
# uses the arping() function from scapy, sends an ARP request to the target IP
def arp_scan(ip_list):
    arplist = []  # To store IP-MAC mappings

    """Perform ARP scan on local network."""
    for ip in ip_list:
        resp, _ = arping(ip, verbose=False)
        print(f"send packet to {ip}")
        for sent, received in resp:
            mac_address = received.hwsrc
            print(f"Host {received.psrc} - MAC: {mac_address}")
            arplist.append({'IP': received.psrc, 'MAC': mac_address})
    
    # Print summary of all active hosts and their MAC addresses
    if arplist:
        print("\nSummary of Active Hosts:")
        for entry in arplist:
            print(f"Host {entry['IP']} - MAC {entry['MAC']}")
    else:
        print("No active hosts discovered.")


def get_user_input():
    print("Supported IP formats: CIDR (10.0.0.1/24), Range (10.0.0.1-10.0.0.255), Single IP (10.0.0.1).")
    ip_range = input("Enter target IP address or range: ")
    ip_list = validate_ip_range(ip_range)
    if not ip_list:
        return

    print("Select scan type:")
    print("1. TCP Scan (Common Ports 22, 80, 443)")
    print("2. ARP Scan (No fire wall blocking)")
  

    choice = input("Enter option (1, 2,): ")
    if choice == "1":
        tcp_scan(ip_list)
    elif choice == "2":
        arp_scan(ip_list)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    get_user_input()
