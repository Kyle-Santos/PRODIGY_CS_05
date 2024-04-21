from scapy.all import *
import datetime

# Enable libpcap support
conf.use_pcap = True
packet_number = 1

# Define a packet callback function
def packetCallback(packet):
    global packet_number
    time=datetime.datetime.now()

    try:
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extract protocol information
        protocol = packet[IP].proto

        # get payload
        if packet.haslayer(TCP):
            payload_len = len(packet[TCP])
        elif packet.haslayer(UDP):
            payload_len = len(packet[UDP])
        elif packet.haslayer(ICMP):
            payload_len = len(packet[ICMP])
        else:
            payload_len = 0

        # display the packet
        print(f"[{packet_number}] [{time}] Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload_len} Bytes")
        
        # update the packet number
        packet_number += 1
    except:
        pass    

# Sniff packets and invoke the packet callback function
def sniffPackets(interface="en0"):
    packets = sniff(iface=interface, prn=packetCallback, store=True)

    # Write the sniffed packets to a pcap file
    wrpcap("packetsCapture.pcap", packets)

# Main function
def main():
    interface = input("Enter the interface to sniff (e.g., eth0, lo0, en0): ")
    sniffPackets(interface)

if __name__ == "__main__":
    main()
