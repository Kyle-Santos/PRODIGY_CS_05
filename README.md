# PRODIGY_CS_05

## Network Packet Analyzer | Prodigy InfoTech Internship
This Python script allows you to sniff network packets on a specified interface and display information about each packet.

### Requirements
1. Python 3.x
2. scapy library (pip install scapy)

### Usage
1. Clone the repository or download the script packet_sniffer.py.
2. Install the required dependencies using pip install scapy.
3. Run the script by executing:

    ```
    python PacketAnalyzer.py.
    ```
4. Enter the interface name (e.g., eth0, lo0, en0) when prompted.
5. The script will start sniffing packets on the specified interface and display packet information in the console.

### Features
1. Displays source and destination IP addresses, protocol, and payload size for each packet.
2. Writes sniffed packets to a pcap file named packetsCapture.pcap for further analysis.

### Customization
1. You can customize the packet callback function (packetCallback) to extract additional information from packets or perform specific actions based on packet content.
2. Modify the interface selection method in the main function to suit your needs.

### Disclaimer
This script is provided for educational and informational purposes only. Do not use it for any illegal or malicious activities. Always respect the privacy and security of others.

