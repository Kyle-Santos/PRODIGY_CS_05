from scapy.all import *
import datetime

# Enable libpcap support
conf.use_pcap = True
i = 1

# Define a packet callback function
def packetCallback(packet):
    global i
    time=datetime.datetime.now()

    try:
        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extract protocol information
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            print(f"[{i}] [{time}] Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {format(len(packet[TCP]))} Bytes")

        if packet.haslayer(UDP):
            print(f"[{i}] [{time}] Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {format(len(packet[UDP]))} Bytes")

        if packet.haslayer(ICMP):
            print(f"[{i}] [{time}] Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {format(len(packet[ICMP]))} Bytes")
        
        i += 1
    except:
        pass    

# Sniff packets and invoke the packet callback function
def sniffPackets(interface="en0"):
    packets = sniff(iface=interface, prn=packetCallback, store=True)

    # Write the sniffed packets to a pcap file
    wrpcap("packetsCapture.pcap", packets)

# Main function
def main():
    interface = input("Enter the interface to sniff (e.g., eth0, lo0): ")
    sniffPackets(interface)

if __name__ == "__main__":
    main()
