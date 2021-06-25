from scapy.all import *


def capturing_packet(captured_packet):
    print(captured_packet.show())

sniff(filter="10.0.2.15",prn=capturing_packet)
#sniff(filter="10.0.2.15", count=10).summary()