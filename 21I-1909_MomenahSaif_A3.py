import os
from scapy.all import *
import subprocess
import re
import scapy.all as scapy
import nmap
import shutil

def generate_ip_range(start_ip, end_ip):     #generates 10 more ips from the start ip, used in icmp ping sweep
    start = list(map(int, start_ip.split('.')))
    end = list(map(int, end_ip.split('.')))
    for i in range(start[0], end[0] + 1):
        for j in range(start[1], end[1] + 1):
            for k in range(start[2], end[2] + 1):
                for l in range(start[3], end[3] + 1):
                    yield f"{i}.{j}.{k}.{l}"


def arp_ping_scan(target):
    print("-----Performing ARP Ping Scan------")
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)# Create ARP request packet
        response = srp(arp_request, timeout=2, verbose=False)[0]# Send packet and wait for response
        devices = []# Extract MAC addresses from response
        for _, rcv in response:
            devices.append({'ip': rcv.psrc, 'mac': rcv.hwsrc})
        print("ARP scan successful:")# Print the results
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
        return True, devices
    except Exception as e:    #failed to perform th scan,te packet was not sent
        print("ARP scan failed:", e)
        return False, []


def icmp_echo_ping(target):
    print("-------Performing ICMP Echo Ping-------")
    try:
        ans, _ = sr(IP(dst=target)/ICMP(), timeout=2, verbose=False)# Send ICMP Echo Request   
        responding_ips = [response[IP].src for request, response in ans]# Extract responding IPs
        print("ICMP Echo Ping scan successful:")# Print the results
        for ip in responding_ips:
            print(f"Responding IP: {ip}")
        return True, responding_ips
    except Exception as e:#failed to perform th scan,te packet was not sent
        print("ICMP Echo Ping scan failed:", e)
        return False, []

def icmp_echo_ping_sweep(target):
    print("IP: ",target)
    responding_ips = []
    try:
        result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)# Running the ping command      
        if result.returncode == 0:# Parsing the output to extract responding IP addresses
            lines = result.stdout.splitlines()
            for line in lines:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(0)
                    responding_ips.append(ip)  
        if responding_ips:# Print the results
            print("ICMP Echo Ping Sweep successful")
            return True, responding_ips
        else:
            print("The IP didn't responded to ICMP Echo Ping Sweep")
            return False, []

    except Exception as e:#failed to perform th scan,te packet was not sent
        print("ICMP Echo Ping Sweep failed:", e)
        return False, []

def icmp_timestamp_ping(target):
   print("-------Performing ICMP Timestamp Ping-------")
   responding_ips = []
   try:
      result = subprocess.run(['ping', '-c', '4', target], capture_output=True, text=True)#Running the ping command with time
      if result.returncode == 0:# Parsing the output to extract responding IP addresses and timestamps
            lines = result.stdout.splitlines()
            for line in lines:
                match = re.search(r'icmp_seq=\d+ ttl=\d+ time=(\d+\.\d+) ms', line)
                if match:
                    timestamp = float(match.group(1))
                    responding_ips.append((target, timestamp))       
      if responding_ips:# Print the results
         print("ICMP Timestamp Ping successful:")
         for ip, timestamp in responding_ips:
             print(f"Responding IP: {ip}, Timestamp: {timestamp} ms")
         return True, responding_ips
      else:
           print("No IPs responded to ICMP Timestamp Ping")
           return False, []

   except Exception as e:
        print("ICMP Timestamp Ping failed:", e)
        return False, []


def icmp_address_mask_ping(target_ip):#rarely used in modern networks, often turned off by OS, which is why couldn't mostly get the respose packet
    print("-------Performing ICMP Address Mask Ping-------")
    try:# Sending ICMP address mask request
        response = sr1(IP(dst=target_ip)/ICMP(type=8, code=0)/Raw(load=b'\x01\x01\x00\x00\x00\x00'), timeout=2, verbose=False)
        if response:
            print("ICMP Address Mask Ping successful for", target_ip)
            if response[ICMP].type == 18:  # Using numeric value for ICMP_MASKREPLY
                subnet_mask = response[ICMP].mask
                print("Subnet Mask:", subnet_mask)
            else:
                print("Received ICMP type:", response[ICMP].type)
        else:
            print("ICMP Address Mask Ping unsuccessful for", target_ip)
    except Exception as e:
        print("ICMP Address Mask Ping failed:", e)

def udp_ping_scan(target, start_port=130, end_port=150, retries=1):#range of ports,retries used because from one packet the reponse was not recived
    print("-------Performing UDP Port Scan--------")
    for port in range(start_port, end_port + 1):
        udp_packets = [# Craft UDP packets with different payloads
            #IP(dst=target) / UDP(dport=port) / Raw(load="Hello"),
            IP(dst=target) / UDP(dport=port) / DNS(qd=DNSQR(qname="example.com"))]
        for udp_packet in udp_packets:
            #for attempt in range(retries):
                try:            
                    response = sr1(udp_packet, timeout=1, verbose=0)# Send the packet and receive the response
                    if response:        
                        if response.haslayer(UDP):# If a response is received, analyze it
                            print("UDP Port open:", port)
                            break  # Exit the retry loop if port is detected as open
                        elif response.haslayer(ICMP):          
                            if int(response[ICMP].tye) == 3 and int(response[ICMP].code) in [3, 13]:# If the response is an ICMP packet (potentially port unreachable)
                                print("UDP Port closed:", port)
                                break  # Exit the retry loop if port is detected as closed
                            else:
                                print("UDP Port filtered:", port)
                                break  # Exit the retry loop if port is detected as filtered
                        else:
                            print("UDP Port open/filtered:", port)
                    else:   
                        print("UDP Port open/filtered:", port)# If no response is received, the port may be open or filtered
                except Exception as e:
                    print("Error:", e)# If an error occurs, handle it and continue to next attempt
                    #continue


def tcp_syn_scan(target, start_port=100, end_port=150, timeout=2):
    print("-------Performing TCP SYN Scan--------")
    open_ports = []
    for port in range(start_port, end_port + 1):       
        syn_packet = IP(dst=target) / TCP(dport=port, flags="S")# Craft a SYN packet
        try:
            response = sr1(syn_packet, timeout=timeout, verbose=0)# Send the packet and receive the response
            if response and response.haslayer(TCP):              
                if response[TCP].flags == 0x12:# Check if the TCP packet has the SYN-ACK flag set
                    open_ports.append(port)
                    print("TCP Port open:", port)          
                elif response[TCP].flags == 0x14:
                    print("TCP Port closed:", port)# Check if the TCP packet has the RST flag set
        except Exception as e:
            print("Error:", e)
    print("All Open ports:", open_ports)

def tcp_ack_scan(target):
    print("-------Performing TCP Ack Scan-------")
    port_range = range(100, 150)
    for port in range(port_range[0], port_range[49]+1):
        response = sr1(IP(dst=target)/TCP(dport=port, flags="A"), timeout=1, verbose=0)
        if response is None:
            print("TCP Port filtered or closed:", port)
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 4: # RST flag set
                print("TCP Port closed:", port)
            elif response.getlayer(TCP).flags == 20: # RST and ACK flags set
                print("TCP Port open:", port)
        else:
            print("TCP Port status unknown:", port)

def tcp_null_scan(target):
    print("-------Performing TCP Null Scan---------")
    port_range = (100, 150)
    for port in range(port_range[0], port_range[1] + 1):
        response = sr1(IP(dst=target)/TCP(dport=port, flags=""), timeout=1, verbose=0)
        if response is None:
            print("TCP Port filtered or open:", port)
        elif response.haslayer(TCP):
            if response.getlayer(TCP).flags == 4: # RST flag set
                print("TCP Port closed:", port)
            else:
                print("TCP Port open or filtered:", port)
        else:
            print("TCP Port status unknown:", port)
            
def check_os(target_ip,system):#used for XMAS,FIN
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-p 139 -O')  # Perform OS detection  #sudo nmap -p 1-1000 -sS 192.168.100.68 (use the command to know open port and enter it instead of 139)
    if target_ip in nm.all_hosts():
        os_guess = nm[target_ip]['osmatch']
        for os_info in os_guess:
            if 'osclass' in os_info:
                for os_class in os_info['osclass']:
                    if 'osfamily' in os_class and os_class['osfamily'] == system:
                        print(f"{target_ip} is running .")
                        return True
    print(f"{target_ip} is not running.")
    return False
    
    
    
def tcp_xmas_scan(target):
    print("-------Performing TCP XMAS Scan---------")
    if check_os(target,"Windows"):
        print("Target is running Windows. XMAS scan not possible.")
        return
    ports = [i for i in range(1, 11)]     
    xmas_packet = IP(dst=target) / TCP(dport=ports, flags="FPU")
    
    # Send the packet and wait for responses
    response = scapy.sr(xmas_packet, timeout=2, verbose=False)[0]

    open_ports = []
    for packet in response:
        # Check if the TCP layer exists in the response and if the RST flag is set
        if packet.haslayer(TCP) and packet[TCP].flags == 0x14:
            open_ports.append(packet[TCP].sport)
            
    if open_ports:
            print("Open ports:", open_ports)
    else:
         print("No open ports found.")        


def tcp_fin_scan(target):
    print("--------Performing TCP FIN Scan--------")
    if check_os(target,"UNIX"):
        print("Target is running on UNIX")
        open_ports = []
        for port in range(100, 151):# Loop through the port range and perform TCP FIN scan
            response = sr1(IP(dst=target)/TCP(dport=port, flags="F"), timeout=2, verbose=False)
            if response and response.haslayer(TCP):
               if response[TCP].flags == 0x14:  # RST-ACK response
                  print(f"Port {port} is closed.")
               elif response[TCP].flags == 0x04:  # RST response
                    print(f"Port {port} is open.")
                    open_ports.append(port)
            else:
                print(f"No response from port {port}.")

        if open_ports:
           print("Open ports:", open_ports)
        else:
            print("No open ports found.")
    else:
         print("FIN only works on UNIX and IP is not of UNIX.")
         
         
def icmp_ping_scan(target):
    print("----Performing ICMP Ping Scan------")
    ans, _ = sr(IP(dst=target)/ICMP(), timeout=2)
    for resp in ans:
        print(resp[0][IP].src, "is up")

def ip_ping_scan(target):
    print("----Performing IP Ping Scan------")
    ans, _ = sr(IP(dst=target)/IP(proto=0), timeout=2)
    for resp in ans:
        print(resp[0][IP].src, "is up")

def tcp_ping_scan(target, port=80):
    print("-----Performing TCP Ping Scan------")
    ans, _ = sr(IP(dst=target)/TCP(dport=port, flags="S"), timeout=2)
    for resp in ans:
        if resp[1].haslayer(TCP) and resp[1][TCP].flags == 18: # 18 corresponds to SYN+ACK
            print(resp[0][IP].src, "is up")

def ip_protocol_ping_scan(target):#Calling all IP scans
    print("Performing IP Protocol Ping Scan on", target)
    icmp_ping_scan(target)
    ip_ping_scan(target)
    tcp_ping_scan(target)

def print_centered(text, color_code):#Def to make the name of tool
    terminal_width = shutil.get_terminal_size().columns# Get the width of the terminal window  
    left_padding = (terminal_width - len(text)) // 2# Calculate the left padding to center the text    
    print("\033[{}m{}{}\033[0m".format(color_code, " " * left_padding, text))# Print the text with the specified color and centered alignment
    
def print_menu():
    print("-" * shutil.get_terminal_size().columns)
    print_centered("Network Discovery Tool", 92)  # 92 is the ANSI color code for green
    print_centered("Made by Momenah Saif-21I-1909", 96)  # 96 is the ANSI color code for cyan
    print("-" * shutil.get_terminal_size().columns)
    print("Menu of Host Discovery Techniques:")
    print("1. ARP Ping Scan")
    print("2. ICMP Ping Scan")
    print("3. UDP Ping Scan")
    print("4. TCP Ping Scan")
    print("5. IP Protocol Ping Scan")
    print("0. Exit")

def main():
    print_menu()
    target = input("Enter target IP address to start the scanning tool: ")
    start_ip_parts = list(map(int, target.split('.')))
    end_ip_parts = start_ip_parts[:]
    end_ip_parts[3] += 10 
    end_ip_parts[3] = min(end_ip_parts[3], 255)# Ensure that the last part doesn't exceed 255
    end_ip = '.'.join(map(str, end_ip_parts))# Convert the end IP parts to string
    
    while True:
        print("\n","*" * 40)
        option = input("Enter your choice from the menu: ")

        if option == '1':
            arp_ping_scan(target)
        elif option == '2':
            print("Select ICMP Ping Scan Type:")
            print("1. ICMP Echo Ping")
            print("2. ICMP Echo Ping Sweep")
            print("3. ICMP Timestamp Ping")
            print("4. ICMP Address Mask Ping")
            icmp_option = input("Enter your choice: ")
            if icmp_option == '1':
                icmp_echo_ping(target)
            elif icmp_option == '2':
                print("--------Performing ICMP Echo Ping Sweep--------")
                for ip in generate_ip_range(target, end_ip):
                    icmp_echo_ping_sweep(ip)
            elif icmp_option == '3':
                icmp_timestamp_ping(target)
            elif icmp_option == '4':
                icmp_address_mask_ping(target)
            else:
                print("Invalid option")
        elif option == '3':
            print("UDP Port Scan")
            udp_ping_scan(target)
        elif option == '4':
            print("Select TCP Ping Scan Type:")
            print("1. TCP SYN Scan")
            print("2. TCP Ack Scan")
            print("3. TCP Null Scan")
            print("4. TCP XMAS Scan")
            print("5. TCP FIN Scan")
            tcp_option = input("Enter your choice: ")
            if tcp_option == '1':
                tcp_syn_scan(target)
            elif tcp_option == '2':
                tcp_ack_scan(target)
            elif tcp_option == '3':
                tcp_null_scan(target)
            elif tcp_option == '4':
                tcp_xmas_scan(target)
            elif tcp_option == '5':
                tcp_fin_scan(target)
            else:
                print("Invalid option")
        elif option == '5':
            ip_protocol_ping_scan(target)
        elif option == '0':
            print("Exiting...")
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
