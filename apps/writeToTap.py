
import subprocess, os, sys, StringIO, select
import threading, signal, string, socket, random, struct, fcntl
from packet import Packet
from multiprocessing import  Pipe

def main():


    #parser.add_option("-y", "--bytes", type="eng_float", default=256,
    #                       help="Number of bytes to read/write from/to filedescriptors (for debug purpose) [default=%default]")
    #parser.add_option("-i", "--interval", type="eng_float", default=0.2,
    #                       help="interval in seconds between two packets being sent [default=%default]")
    #parser.add_option("-v", "--verbose",action="store_true", default=False,
    #                       help="verbose mode [default=%default]")

    VERBOSE = True
    bytes = 256
    interval = 0.2
    
    # open the TUN/TAP interface
    tun_fd = open_tun_interface("/dev/net/tun")

    parent_conn, child_conn = Pipe()
    tun = tunnel(child_conn.fileno(), tun_fd, VERBOSE, bytes, interval)
    tun.start()
     
     
def open_tun_interface(tun_device_filename):
            
        tun = os.open(tun_device_filename, os.O_RDWR)
        return tun

class tunnel(threading.Thread):

    def __init__ (self, myPipe, tun_interface, verbose, bytes, interval):

       threading.Thread.__init__(self)

       self.verbose       = verbose 
       self.tun_interface = tun_interface
       self.bytes         = bytes
       self.interval      = interval
       
       open("listenMaster", "w+").close
       self.fd = open("listenMaster", 'r+b')
       self.pipe_fd = myPipe
         
    def run(self) :
       if self.verbose: print "Running the tunnel main function ..."
       try :
            #Opening socket
            sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # bind it
            sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#           #Opening socket
#           udpSock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
#           # bind it
#           udpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	    ###s = socket.socket()
	    ###s.bind((socket.gethostbyname(socket.gethostname()), 1312))
	    ###s.listen(5)
	    ###inputs = [s]
	    ###outputs = []
	    ###while True:
	    ###    r, w, e = select.select(inputs, outputs, [])
	    ###    for sock in r:
	    ###        if sock is s:
	    ###            inputs.append(s.accept()[0])
	    ###        else:
	    ###            print s
	    ###            print s.recv(1024)
  
            while 1:
               (inputready,outputready,exceptionready)= select.select([self.fd,self.pipe_fd],[],[])
               if self.fd in inputready :
                   #payload = list(os.read(self.fd.fileno(), self.bytes))
                   payload = os.read(self.fd.fileno(), self.bytes)
                   if payload:
                            print "payload at Master: ", payload       
                            #payload = "".join(payload)        
                            #if self.verbose: print "type(payload): ", type(payload)
                            ip_header = payload[0:20]
                            (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
                            #destIpAddr = str(socket.inet_ntoa(iph[9]))        
                            if protocol == 1:
                                if self.verbose: Packet.printIpHeader(payload)
                                packet = payload       
                                icmp_type,icmp_code,icmp_identifier,icmp_sequence = Packet.unpackIcmpHeader(packet,iph_length)
                                # type 8 is echo request
                                if icmp_type == 8 : 
                                    reply = Packet.createIcmpReply(packet)
                                    #if self.verbose: 
                                       #print "got an echo request replying with echo response"
                                       #Packet.printIpHeader(reply)
                                    #os.write(self.tun_interface, reply)
                                    destIpAddr = str(socket.inet_ntoa(iph[9]))
                                    srcIpAddr = str(socket.inet_ntoa(iph[8]))  
                                    #if self.verbose: print "destIpAddr = str(socket.inet_ntoa(iph[9])) : ", destIpAddr                        
                                sendSock.sendto(reply, (destIpAddr, 55555))
                            else:
                                payload = 'E' + payload                        
                                ip_header = payload[0:20]
                                (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
                                Packet.printIpHeader(payload)
                                destIpAddr = str(socket.inet_ntoa(iph[9]))
                                #os.write(self.tun_interface, payload)         
                                sendSock.sendto(payload, (destIpAddr, 5001))   
                                #udpSock.sendto(payload, (destIpAddr, 5008))   
                   time.sleep(self.interval)
#          udpSock.close()
            sendSock.close()
       finally:
            print "Exitting LOOP !!"

if __name__ == '__main__':
   try:
        main()
   except KeyboardInterrupt:
        pass

