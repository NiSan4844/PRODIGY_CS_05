from scapy.all import sniff, IP, TCP, UDP, Raw
import os

# Function to process packets
def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
        # Determine if the packet is TCP or UDP and get additional information
        if packet.haslayer(TCP):
            protocol_name = "TCP"
            payload = packet[TCP].payload
        elif packet.haslayer(UDP):
            protocol_name = "UDP"
            payload = packet[UDP].payload
        else:
            protocol_name = "Other"
            payload = None
        
        # Display captured packet information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol_name}")
        
        # Print payload data if available
        if payload and Raw in payload:
            print(f"Payload Data: {payload[Raw].load.decode(errors='ignore')}")
        print("-" * 50)

# Main function to run the sniffer
def start_sniffer(interface=None):
    if interface:
        print(f"Starting packet sniffer on interface: {interface}")
    else:
        print("Starting packet sniffer on default interface")

    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, filter="ip", store=0)

if __name__ == "__main__":
    # You can specify the network interface if needed
    network_interface = None  # e.g., 'eth0' or 'wlan0'
    
    # Ensure the script runs with sufficient privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run it with sudo.")
    else:
        start_sniffer(network_interface)
