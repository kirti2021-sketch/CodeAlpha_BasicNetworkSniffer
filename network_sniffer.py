from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# Packet counters
total_packets = 0
tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

# Store packet details
packet_details = []


def process_packet(packet):
    global total_packets
    global tcp_count, udp_count, icmp_count, other_count

    if IP in packet:
        total_packets += 1

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        if TCP in packet:
            protocol = "TCP"
            tcp_count += 1

        elif UDP in packet:
            protocol = "UDP"
            udp_count += 1

        elif ICMP in packet:
            protocol = "ICMP"
            icmp_count += 1

        else:
            protocol = "Other"
            other_count += 1

        # Display packet information
        print("\n========== Network Packet ==========")
        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Protocol:", protocol)
        print("Packet Size:", packet_size, "bytes")

        # Save packet information
        details = (
            f"Packet Number: {total_packets}\n"
            f"Source IP: {source_ip}\n"
            f"Destination IP: {destination_ip}\n"
            f"Protocol: {protocol}\n"
            f"Packet Size: {packet_size} bytes\n"
            "------------------------------------\n"
        )

        packet_details.append(details)


def start_sniffer():
    print("====================================")
    print("       BASIC NETWORK SNIFFER")
    print("====================================")

    print("\nCapturing 10 network packets...")
    print("Please wait...\n")

    try:
        sniff(
            filter="ip",
            prn=process_packet,
            count=10,
            store=False
        )

        # Display summary
        print("\n========== PACKET SUMMARY ==========")
        print("Total Packets:", total_packets)
        print("TCP:", tcp_count)
        print("UDP:", udp_count)
        print("ICMP:", icmp_count)
        print("Other:", other_count)

        # Save report
        with open("packet_report.txt", "w") as file:
            file.write("BASIC NETWORK SNIFFER REPORT\n")
            file.write("Date and Time: " + str(datetime.now()) + "\n")
            file.write("====================================\n\n")

            for details in packet_details:
                file.write(details)

            file.write("\n========== PACKET SUMMARY ==========\n")
            file.write(f"Total Packets: {total_packets}\n")
            file.write(f"TCP: {tcp_count}\n")
            file.write(f"UDP: {udp_count}\n")
            file.write(f"ICMP: {icmp_count}\n")
            file.write(f"Other: {other_count}\n")

        print("\nReport saved successfully!")
        print("File Name: packet_report.txt")
        print("\nPacket capturing completed!")

    except PermissionError:
        print("Error: Please run VS Code as Administrator.")

    except Exception as error:
        print("An error occurred:", error)


if __name__ == "__main__":
    start_sniffer()