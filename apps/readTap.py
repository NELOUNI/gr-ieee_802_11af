# ...
#  /* tunclient.c */
#
#  char tun_name[IFNAMSIZ];
#  
#  /* Connect to the device */
#  strcpy(tun_name, "tun77");
#  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);  /* tun interface */
#
#  if(tun_fd < 0){
#    perror("Allocating interface");
#    exit(1);
#  }
#
#  /* Now read data coming from the kernel */
#  while(1) {
#    /* Note that "buffer" should be at least the MTU size of the interface, eg 1500 bytes */
#    nread = read(tun_fd,buffer,sizeof(buffer));
#    if(nread < 0) {
#      perror("Reading from interface");
#      close(tun_fd);
#      exit(1);
#    }
#
#    /* Do whatever with the data */
#    printf("Read %d bytes from device %s\n", nread, tun_name);
#  }
#
#  ...
import struct, os, sys
from fcntl import ioctl
from packet import Packet

IFF_TUN         = 0x0001   # tunnel IP packets
IFF_TAP         = 0x0002   # tunnel ethernet frames
IFF_NO_PI       = 0x1000   # don't pass extra packet info
IFF_ONE_QUEUE   = 0x2000   # beats me ;)

def open_tun_interface():
    
    mode = IFF_TAP | IFF_NO_PI
    TUNSETIFF = 0x400454ca

    tun = os.open("/dev/net/tun", os.O_RDWR)
    #ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "tap1", mode))
    #ifname = ifs[:16].strip("\x00")
    #return (tun, ifname)
    return tun	

def main():
	try:
	        tun_fd = open_tun_interface()	
		while True:
			payload = os.read(tun_fd, 256)
			Packet.printIpHeader(payload)	
	
        finally:
            print "Exitting LOOP !!"

if __name__ == '__main__':
   try:
        main()
   except KeyboardInterrupt:
        sys.exit(0)

