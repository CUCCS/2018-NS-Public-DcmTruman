import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#---------------------
DST_IP = "192.168.56.20"
SRC_PORT = RandShort()
DST_PORT = 53
#--------------------

def tcp_connect_scan(dst_ip , dst_port , timeout = 5 , src_port = SRC_PORT):
    #The function sr1() is a variant that only returns one packet that answered the packet (or the packet set) sent
    #The client sends the first handshake using the SYN flag and port to connect to the server in a TCP packet
    tcp_connect_scan_resp = sr1(IP(dst = dst_ip) / TCP(sport = src_port , dport = dst_port , flags = "S") , timeout = timeout)
    if (str(type(tcp_connect_scan_resp)) == "<type 'NoneType'>"):
       print "Closed"
    elif (tcp_connect_scan_resp.haslayer(TCP)):
        #If the server responds with a RST instead of a SYN-ACK, then that particular port is closed on the server.
        if (tcp_connect_scan_resp.getlayer(TCP).flags == 'AS'):#ACK && SYN : 0x12
            send_rst = sr1(IP(dst=dst_ip)/TCP(sport = src_port , dport=dst_port,flags="AR"),timeout=timeout)
            print "tcp_connect_scan : Open"
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 'AR'):#ACK && RST : 0x14
            print "tcp_connect_scan : Close"

def tcp_stealth_scan(dst_ip , dst_port , timeout = 5 , src_port = SRC_PORT):
    #This technique is similar to the TCP connect scan. The client sends a TCP packet with the SYN flag set and the port number to connect to
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=timeout)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
        print "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        #If the port is open, the server responds with the SYN and ACK flags inside a TCP packet
        if(stealth_scan_resp.getlayer(TCP).flags == 'AS'):#ACK && SYN : 0x12
            #But this time the client sends a RST flag in a TCP packet and not RST+ACK, which was the case in the TCP connect scan. This technique is used to avoid port scanning detection by firewalls.
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=timeout)
            print "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 'AR'):#ACK && RST : 0x14
            #The closed port check is same as that of TCP connect scan. The server responds with an RST flag set inside a TCP packet to indicate that the port is closed on the server
            print "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        #ICMP type 3, Destination unreachable message
        #code 1 : Host unreachable error.
        #code 2 : Protocol unreachable error.Sent when the designated transport protocol is not supported.
        #code 3 : Port unreachable error. Sent when the designated transport protocol is unable to demultiplex the datagram but has no protocol mechanism to inform the sender.
        #code 9 : The destination network is administratively prohibited.
        #code 10 : The destination host is administratively prohibited.
        #code 13 : Communication Administratively Prohibited.This is generated if a router cannot forward a packet due to administrative filtering.
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Filtered"

def xmas_scan(dst_ip , dst_port , timeout = 5,src_port = SRC_PORT):
    #In the XMAS scan, a TCP packet with the PSH, FIN, and URG flags set, along with the port to connect to, is sent to the server.
    xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=10)
    #If the port is open, then there will be no response from the server.
    if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
        print "Open|Filtered"
    elif(xmas_scan_resp.haslayer(TCP)):
        #If the server responds with the RST flag set inside a TCP packet, the port is closed on the server.
        if(xmas_scan_resp.getlayer(TCP).flags == 'AR'):#
            print "Closed"
    elif(xmas_scan_resp.haslayer(ICMP)):
        #If the server responds with the ICMP packet with an ICMP unreachable error type 3 and ICMP code 1, 2, 3, 9, 10, or 13, then the port is filtered and it cannot be inferred from the response whether the port is open or closed.
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Filtered"
def fin_scan(dst_ip , dst_port , timeout = 5 , src_port = SRC_PORT):
    #The FIN scan utilizes the FIN flag inside the TCP packet, along with the port number to connect to on the server
    fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=timeout)
    # If there is no response from the server, then the port is open.
    if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
        print "Open|Filtered"

    elif(fin_scan_resp.haslayer(TCP)):
        #If the server responds with an RST flag set in the TCP packet for the FIN scan request packet, then the port is closed on the server.
        if(fin_scan_resp.getlayer(TCP).flags == 'AR'):#ACK && RST : 0x14
            print "Closed"
    elif(fin_scan_resp.haslayer(ICMP)):
        #An ICMP packet with ICMP type 3 and code 1, 2, 3, 9, 10, or 13 in response to the FIN scan packet from the client means that the port is filtered and the port state cannot be found.
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Filtered"

def null_scan(dst_ip , dst_port , timeout = 5 , src_port = SRC_PORT):
    #In a NULL scan, no flag is set inside the TCP packet. The TCP packet is sent along with the port number only to the server.
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=timeout)
    #If the server sends no response to the NULL scan packet, then that particular port is open.
    if (str(type(null_scan_resp))=="<type 'NoneType'>"):
        print "Open|Filtered"
    #If the server responds with the RST flag set in a TCP packet, then the port is closed on the server.
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 'AR'):#ACK && RTS : 0x14
            print "Closed"

    #An ICMP error of type 3 and code 1, 2, 3, 9, 10, or 13 means the port is filtered on the server.
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Filtered"

def tcp_ack_scan(dst_ip , dst_port , timeout = 5,src_port = SRC_PORT):
    #The TCP ACK scan is not used to find the open or closed state of a port; rather, it is used to find if a stateful firewall is present on the server or not. It only tells if the port is filtered or not. This scan type cannot find the open/closed state of the port.

    #A TCP packet with the ACK flag set and the port number to connect to is sent to the server.
    ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags='A'),timeout=timeout)
    if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
        print "Stateful firewall presentn(Filtered)"

    # If the server responds with the RST flag set inside a TCP packet, then the port is unfiltered and a stateful firewall is absent.
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 'R'):#RST : 0x04
            print "No firewalln(Unfiltered)"

    #if it responds with a TCP packet with ICMP type 3 or code 1, 2, 3, 9, 10, or 13 set, then the port is filtered and a stateful firewall is present.
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print "Stateful firewall presentn(Filtered)"

def tcp_window_scan(dst_ip , dst_port , timeout = 5,src_port = SRC_PORT):
    #A TCP window scan uses the same technique as that of TCP ACK scan.
    # It also sends a TCP packet with the ACK flag set and the port number to connect to
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=timeout)


    if (str(type(window_scan_resp))=="<type 'NoneType'>"):
        print "No response"


    # in a TCP windows scan, when an RST is received from the server, it then checks the value of the windows size.
    elif(window_scan_resp.haslayer(TCP)):

        #If the windows size of the TCP packet with the RST flag set to zero, then the port is closed on the server.
        if(window_scan_resp.getlayer(TCP).window == 0):
            print "Closed"

        #If the value of window size is positive, then the port is open on the server.
        elif(window_scan_resp.getlayer(TCP).window > 0):
            print "Open"

def udp_scan(dst_ip,dst_port,dst_timeout = 5):
    #The client sends a UDP packet with the port number to connect to
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)

    #If the server sends no response to the client's UDP request packets for that port,it can be concluded that the port on the server is either open or filtered
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        print "Open|Filtered"
    #If the server responds to the client with a UDP packet, then that particular port is open on the server.
    elif (udp_scan_resp.haslayer(UDP)):
        print "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        #the server responds with an ICMP port unreachable error type 3 and code 3, meaning that the port is closed on the server.
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            print "Closed"
    
        #If the server responds to the client with an ICMP error type 3 and code 1, 2, 9, 10, or 13, then that port on the server is filtered.
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            print "Filtered"
    elif(udp_scan_resp.haslayer(IP) and udp_scan_resp.getlayer(IP).proto==IP_PROTOS.udp):
        print "Open"

def main():
    #dst_ip = DST_IP
    #src_port = SRC_PORT
    #dst_port = DST_PORT
    #send_rst = sr1(IP(dst=DST_IP)/TCP(sport = SRC_PORT , dport=DST_PORT,flags="AR"),timeout=5)
    #tcp_connect_scan_resp = sr1(IP(dst = dst_ip) / TCP(sport = src_port , dport = dst_port , flags = "S") , timeout = 10)
    #tcp_connect_scan(DST_IP , DST_PORT , timeout = 5)
    #xmas_scan(DST_IP , DST_PORT , timeout = 5)
    #fin_scan(DST_IP , DST_PORT , timeout = 5)
    #null_scan(DST_IP , DST_PORT , timeout = 5)
    #tcp_ack_scan(DST_IP , DST_PORT , timeout = 5)
    #tcp_window_scan(DST_IP , DST_PORT , timeout = 5)
    udp_scan(DST_IP,DST_PORT)
if __name__ == "__main__":
    main()