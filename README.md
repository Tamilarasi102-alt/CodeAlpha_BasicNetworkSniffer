\# CodeAlpha Basic Network Sniffer



A Python-based basic network sniffer developed as part of the CodeAlpha Cyber Security Internship.



\## Project Overview



This project captures and analyzes network packets in real time using the Scapy library.



The sniffer displays important packet information such as:



\- Packet number

\- Timestamp

\- Source IP address

\- Destination IP address

\- Source port

\- Destination port

\- Network protocol

\- Payload size

\- Payload preview

\- Protocol statistics



The program captures up to 50 packets and then displays a summary of the captured traffic.



\## Features



\- Real-time packet capture

\- TCP packet detection

\- UDP packet detection

\- ICMP packet detection

\- ARP packet detection

\- Source and destination IP identification

\- Source and destination port identification

\- Payload size analysis

\- Safe payload preview

\- Protocol statistics

\- Automatic capture limit

\- Graceful termination using CTRL+C



\## Technologies Used



\- Python 3

\- Scapy

\- Npcap

\- Windows PowerShell



\## Project Structure



```text

CodeAlpha\_BasicNetworkSniffer/

│

├── sniffer.py

├── requirements.txt

├── README.md

└── screenshots/

