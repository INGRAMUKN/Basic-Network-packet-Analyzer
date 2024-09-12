Network Packet Analyzer
---------------------------
Description
------------
This project is an advanced C++ network packet analyzer that uses the libpcap library to capture and analyze network packets in real-time. It can dissect Ethernet, IP, TCP, UDP, and ICMP packets, providing detailed information about each captured packet.
Features

Capture packets from a specified network interface
Analyze Ethernet frames
Decode IP packets
Inspect TCP, UDP, and ICMP protocols
Display packet details including source/destination IP addresses, ports, and protocol-specific information

Prerequisites
-------------
To compile and run this program, you need:

A C++ compiler (g++ recommended)
libpcap library and development files
Root/administrator privileges (for packet capturing)

Installation
-------------
On Ubuntu/Debian:
-----------------
bashCopysudo apt-get update
sudo apt-get install g++ libpcap-dev

On macOS (using Homebrew):
--------------------------
bashCopybrew install gcc libpcap

Compilation
------------
To compile the program, navigate to the directory containing the source file and run:
bashCopyg++ -o packet_analyzer packet_analyzer.cpp -lpcap

This will create an executable named packet_analyzer.

Usage
-------

Run the program with root privileges, specifying the network interface to capture packets from:
bashCopysudo ./packet_analyzer <interface_name>
Replace <interface_name> with the name of your network interface (e.g., eth0, wlan0).
To stop the program, press Ctrl+C.

Example Output
---------------
Copy=== New Packet Captured ===
Packet length: 74 bytes
Ethernet type: 2048
IP Header:
  Source IP: 192.168.1.100
  Destination IP: 93.184.216.34
TCP Header:
  Source Port: 54321
  Destination Port: 80
  Sequence Number: 1234567890
  Acknowledgment Number: 0987654321
  Flags: SYN ACK
  
Warning
-----------
Capturing network packets may have legal and ethical implications. Ensure you have permission to capture traffic on the network and interface you're using.

Thank you
Malak Elkhouli
