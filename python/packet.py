import struct
import socket
import dpkt

#############################################
# Packet dump utility
#############################################

class Packet(object):
    def unpackIpHeader(ip_header):
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        protocol = iph[6]
        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        packet_length = iph[2]
        src_ip = ip_header[12:16]
        dst_ip = ip_header[16:20]
        return (iph, protocol,iph_length,packet_length, src_ip,dst_ip)

    unpackIpHeader = staticmethod (unpackIpHeader)

    def  unpackIcmpHeader(packet,iph_length):
        icmp_header = packet[iph_length:iph_length+8]
        #now unpack them :)
        icmph = struct.unpack('!BBHHH' , icmp_header)
        icmp_type = icmph[0]
        icmp_code = icmph[1]
        icmp_checksum = icmph[2]
        icmp_identifier = icmph[3]
        icmp_sequence = icmph[4]
        return (icmp_type, icmp_code, icmp_identifier, icmp_sequence)

    unpackIcmpHeader = staticmethod(unpackIcmpHeader)

    def unpackUdpHeader(packet, iph_length):
        print "unpacking udp header"
        udph_length = 8
        udp_header = packet[iph_length:iph_length+8]
        #now unpack them :)
        udph = struct.unpack('!HHHH' , udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]
        print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
        h_size = iph_length + udph_length
        data_size = len(packet) - h_size
        #get data from the packet
        data = packet[h_size:]
        print 'Data : ' + data

    unpackUdpHeader = staticmethod(unpackUdpHeader)

    def createIcmpReply(packet):
        pkt = list(packet)
        # Change ICMP type code to Echo Reply (0).
        pkt[20] = chr(0)
        # Swap source and destination address.
        pkt[12:16], pkt[16:20] = packet[16:20], packet[12:16]
        # Clear original ICMP Checksum field.
        pkt[22:24] = chr(0), chr(0)
        checksum = 0
        # for every 16-bit of the ICMP payload:
        for i in range(20, len(packet), 2):
            half_word = (ord(packet[i]) << 8) + ord(packet[i+1])
            checksum += half_word
            # Get one's complement of the checksum.
            checksum = ~(checksum + 4) & 0xffff
            # Put the new checksum back into the packet.
            pkt[22] = chr(checksum >> 8)
            pkt[23] = chr(checksum & ((1 << 8) -1))
        reply = "".join(pkt)
        return reply

    createIcmpReply = staticmethod(createIcmpReply)

    def printIpHeader(payload) :
        #take first 20 characters for the ip header
        ip_header = payload[0:20]
        #now unpack them :)
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        #version_ihl = iph[0]
        #version = version_ihl >> 4
        #iph_length = ihl * 4
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = iph[2]
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        print 'Version : ' + str(version)       \
        + ' length ' + str(iph_length)          \
        + ' TTL : ' + str(ttl)                  \
        + ' Protocol : ' + str(protocol)        \
        + ' Source Address : ' + str(s_addr)    \
        + ' Destination Address : ' + str(d_addr)

    printIpHeader = staticmethod(printIpHeader)
