from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("IP"):
        print(f"Packet: {packet.summary()}")
        print(f"Source: {packet['IP'].src} -> Destination: {packet['IP'].dst}")
        print(f"Protocol: {packet['IP'].proto}\n")

print("Opening the network sniffer")
sniff(prn=packet_callback, store=False)