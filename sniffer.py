from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from collections import Counter

packet_count = 0
protocol_count = Counter()

MAX_PAYLOAD_PREVIEW = 40


def get_payload_preview(packet):
    if IP not in packet:
        return "N/A"

    payload = bytes(packet[IP].payload)

    if not payload:
        return "No payload"

    preview = payload[:MAX_PAYLOAD_PREVIEW]

    return "".join(
        chr(byte) if 32 <= byte <= 126 else "."
        for byte in preview
    )


def process_packet(packet):
    global packet_count

    packet_count += 1

    print("\n" + "=" * 75)
    print(f"Packet #{packet_count}")
    print(f"Time            : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if ARP in packet:
        protocol_count["ARP"] += 1

        print("Protocol        : ARP")
        print(f"Source MAC      : {packet[ARP].hwsrc}")
        print(f"Destination MAC : {packet[ARP].hwdst}")
        print(f"Source IP       : {packet[ARP].psrc}")
        print(f"Destination IP  : {packet[ARP].pdst}")

    elif IP in packet:

        print(f"Source IP       : {packet[IP].src}")
        print(f"Destination IP  : {packet[IP].dst}")

        if TCP in packet:
            protocol_count["TCP"] += 1

            print("Protocol        : TCP")
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            protocol_count["UDP"] += 1

            print("Protocol        : UDP")
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif ICMP in packet:
            protocol_count["ICMP"] += 1

            print("Protocol        : ICMP")

        else:
            protocol = f"IP({packet[IP].proto})"
            protocol_count[protocol] += 1

            print(f"Protocol        : {protocol}")

        payload_size = len(bytes(packet[IP].payload))

        print(f"Payload Size    : {payload_size} bytes")
        print(f"Payload Preview : {get_payload_preview(packet)}")

    else:
        protocol_count["Other"] += 1
        print("Protocol        : Other")


def show_summary():
    print("\n")
    print("=" * 75)
    print("                    CAPTURE SUMMARY")
    print("=" * 75)

    print(f"Total Packets Captured : {packet_count}")

    print("\nProtocol Statistics:")

    for protocol, count in protocol_count.most_common():
        print(f"{protocol:<15}: {count}")

    print("=" * 75)
    print("Network capture completed.")
    print("=" * 75)


print("=" * 75)
print("              CODEALPHA - BASIC NETWORK SNIFFER")
print("=" * 75)
print("Starting packet capture...")
print("Capture limit: 50 packets")
print("Press CTRL+C to stop early.")
print("=" * 75)

try:
    sniff(
        prn=process_packet,
        count=50,
        store=False
    )

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

finally:
    show_summary()