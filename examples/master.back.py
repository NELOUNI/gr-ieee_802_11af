#!/usr/bin/python

# Copyright 2005,2006,2011 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

# Kill eventual Zombie process 
import subprocess, os, sys
try:
        subprocess.call('ps -all | grep -ie \'listenMaster ncat tee\' | awk \'{print $2}\' | xargs sudo kill -9', shell=True) #FIXME ps -all or ps aux
															      #FIXME need to search for ncat, tee too ?
except OSError as e:
    print >>sys.stderr, "Execution failed:", e

execfile("/home/naceur/.grc_gnuradio/wifi_phy_hier.py") #FIXME when calling this script using sudoEnv alias $USER = root, How to retrieve the calling user's home

from gnuradio import blocks, gr, uhd, eng_notation, digital
from gnuradio.eng_option import eng_option
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio.wxgui import forms
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
from multiprocessing import  Pipe
import json, pycurl, StringIO
import pmt, time ,wx, signal
import threading, sys, signal, string, socket, random, struct, fcntl
import webServerWSDB 
from webServerWSDB import app 
import select, psutil
from fcntl import ioctl
import ieee802_11, foo
from packet import Packet
from mac import *


class transceiverMaster(grc_wxgui.top_block_gui):

    def __init__(self, addr, no_usrp, rate, lo_offset, encod, otw, source, no_self_loop, debug_MAC):

	grc_wxgui.top_block_gui.__init__(self, title="TransceiverMaster")
	
        ##################################################
        # Variables
        ##################################################

        self.addr 	  = addr
	self.no_usrp	  = no_usrp
	self.samp_rate	  = rate
	self.otw	  = otw
        self.no_self_loop = no_self_loop	
	self.debug_MAC	  = debug_MAC
	self.lo_offset    = lo_offset
	
        ##################################################
        # Blocks
        ##################################################
	if self.no_usrp:
	   	self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, self.samp_rate*1e6,True)
		################################
		## Using files instead of USRPs
		###############################
	        self.blocks_file_source_Master = blocks.file_source(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/fileSourceMaster"), True)
	        self.blocks_file_sink_Master = blocks.file_sink(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/fileSinkMaster"), False)
	        self.blocks_file_sink_Master.set_unbuffered(False)
	        
	else:
	        ############### 
	        ## usrp_source
	        ###############
	        self.uhd_usrp_source_0 = uhd.usrp_source(",".join((self.addr, "")),
				        		 uhd.stream_args(cpu_format="fc32",
									 otw_format=self.otw,
									 channels=range(1),),)

		# TODO Explain the usage 
                self.uhd_usrp_source_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)

		###############
	        ## usrp_sink
	        ###############
        	self.uhd_usrp_sink_0 = uhd.usrp_sink(",".join((self.addr, "")),
					       	     uhd.stream_args(cpu_format="fc32",
								     otw_format=self.otw,
                        	                                     channels=range(1),), "packet_len",)  
		# TODO Explain the usage 
        	self.uhd_usrp_source_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)

        # 802.11 a,g,p PHY Layer OFDM
        # Encoding choices=[0,1,2,3,4,5,6,7]="BPSK 1/2", "BPSK 3/4", "QPSK 1/2", "QPSK 3/4", "16QAM 1/2", "16QAM 3/4", "64QAM 2/3", "64QAM 3/4"
	print "Encoding used: ", int(encod) #FIXME add the equivalent scheme
        self.PHY = wifi_phy_hier( encoding= int(encod), )

        # Foo block #TODO explain its usage
        self.foo_packet_pad2_0 = foo.packet_pad2(False, False, 0.001, 0, 10000) ## ?! ##
        (self.foo_packet_pad2_0).set_min_output_buffer(100000)

        # Multiply Const Block 
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc((0.38, )) #mult = 0.38
        (self.blocks_multiply_const_vxx_0).set_min_output_buffer(100000)

        # 802.11 a,g,p OFDM MAC Layer
        self.ieee802_11_ofdm_mac_0 = ieee802_11.ofdm_mac(([0x33, 0x33, 0x33, 0x33, 0x33, 0x33]), ([0x32, 0x32, 0x32, 0x32, 0x32, 0x32]), ([0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc])) 

	# ofdm_parse_mac block for debugging purpose TODO Modify it so that it parse the frames structure of the MAC am using
        self.ieee802_11_ofdm_parse_mac_0 = ieee802_11.ofdm_parse_mac(False, True)

        # Ethernet Encapsulation #TODO explain its usage 
        self.ieee802_11_ether_encap_0 = ieee802_11.ether_encap(True)

        # ///////////////////////////////////////////////////////////////////////////////////////////////////////
        #   Set virtual ethernet interface (tap0), relays packets between the interface and the GNU Radio PHY+MAC
        #   Use the Universal TUN/TAP device driver to move packets to/from kernel
        #   See /usr/src/linux/Documentation/networking/tuntap.txt
        # ///////////////////////////////////////////////////////////////////////////////////////////////////////
        if source == "tuntap":
                self.blocks_tuntap_pdu_0 = blocks.tuntap_pdu("tap1", 440, True)
	
        ##################################################
        # Asynch Message Connections
        ##################################################

		self.msg_connect(self.ieee802_11_ether_encap_0, "to tap", self.blocks_tuntap_pdu_0, "pdus")
        	self.msg_connect(self.blocks_tuntap_pdu_0, "pdus", self.ieee802_11_ether_encap_0, "from tap")

 		self.msg_connect(self.ieee802_11_ofdm_mac_0, "app out", self.ieee802_11_ether_encap_0, "from wifi")
		self.msg_connect(self.ieee802_11_ether_encap_0, "to wifi"  , self.ieee802_11_ofdm_mac_0,      "app in")


	else:   # UDP Sockets
		#TODO Test ME ! 
        	self.blocks_socket_pdu_0_Tx = blocks.socket_pdu("UDP_SERVER", "localhost", "52002", 10000)
		self.blocks_socket_pdu_0_Rx = blocks.socket_pdu("UDP_CLIENT", "localhost", "3334", 10000)

 		self.msg_connect(self.ieee802_11_ofdm_mac_0, "app out", self.blocks_socket_pdu_0_Rx,      "pdus")
		self.msg_connect(self.blocks_socket_pdu_0_Tx, "pdus"  , self.ieee802_11_ofdm_mac_0,      "app in")

        ## Debugging at the MAC level To parse at the level of MAC ! Look at the flowgraph
        self.msg_connect(self.PHY, 		     "mac_out", self.ieee802_11_ofdm_parse_mac_0, "in")   #TODO Test me
        self.msg_connect(self.PHY,		     "mac_out", self.ieee802_11_ofdm_mac_0,      "phy in")
        self.msg_connect(self.ieee802_11_ofdm_mac_0, "phy out", self.PHY, 		         "mac_in")

	##################################################
        # Connections
        ##################################################

        if self.no_usrp:
                self.connect((self.PHY, 0), (self.blocks_multiply_const_vxx_0, 0)) 
                self.connect((self.blocks_file_source_Master, 0), (self.PHY, 0)) 
                self.connect((self.foo_packet_pad2_0, 0), (self.blocks_file_sink_Master, 0)) 
                self.connect((self.blocks_multiply_const_vxx_0, 0), (self.foo_packet_pad2_0, 0)) 
        else:
                self.connect((self.PHY, 0), (self.blocks_multiply_const_vxx_0, 0)) 
                self.connect((self.uhd_usrp_source_0, 0), (self.PHY, 0)) 
                self.connect((self.foo_packet_pad2_0, 0), (self.uhd_usrp_sink_0, 0)) 
                self.connect((self.blocks_multiply_const_vxx_0, 0), (self.foo_packet_pad2_0, 0)) 

    	if not self.lo_offset:
    	    self.lo_offset = self.samp_rate / 2.0 
    	print "LO offset set to", self.lo_offset/1e6, "MHz"

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_source_0.set_gain(self.gain, 0)
        self.uhd_usrp_sink_0.set_gain(self.gain, 0)

    def get_freq(self):
	return self.uhd_usrp_source_0.get_center_freq(0)      
    
    def set_freq(self, freq):
        self.freq = freq
        r = self.uhd_usrp_sink_0.set_center_freq(uhd.tune_request(self.freq, rf_freq=(self.freq + self.lo_offset),rf_freq_policy=uhd.tune_request.POLICY_MANUAL))
        g = self.uhd_usrp_source_0.set_center_freq(uhd.tune_request(self.freq, rf_freq=(self.freq + self.lo_offset),rf_freq_policy=uhd.tune_request.POLICY_MANUAL))
	print "USRP Sink ", r
	print "USRP Source ", g

    def set_samp_rate(self, rate):	
	self.rate = rate
	self.uhd_usrp_source_0.set_samp_rate(self.rate)
	self.uhd_usrp_sink_0.set_samp_rate(self.rate)

def getFreqMap(spec_dB, remote_dB):

     if(spec_dB == "google"):
	url = 'https://www.googleapis.com/rpc'
     elif(spec_dB == "local"):
	url = 'http://127.0.0.1:5000/'
     elif(spec_dB == "remote"):  
        url = 'https://'+remote_dB+':5000' #FIXME Option for port and ssl
     
     postdata = []
     buf = StringIO.StringIO()
     with open("utils/postdata.txt", "r") as fpostdata:
           while True:
                c = fpostdata.read(1)
                postdata.append(c) 
                if not c:
                        break
     fpostdata.close()    
     postdata_str = ''.join(postdata)
     c = pycurl.Curl()
     c.setopt(c.HTTPHEADER, ['Accept: application/json', 'Content-Type: application/json','charsets: utf-8'])
     c.setopt(c.URL, url) 

     if(spec_dB == "remote"):
     	c.setopt(pycurl.SSLCERT, "utils/keys/antd.nist.gov.crt")		
     	c.setopt(pycurl.SSLKEY, "utils/keys/antd.nist.gov.pem")		

     	c.setopt(pycurl.SSL_VERIFYPEER, 0)
     	c.setopt(pycurl.SSL_VERIFYHOST, 2)

     # send all data to this function
     c.setopt(c.WRITEFUNCTION, buf.write)
     # some servers don't like requests that are made without a user-agent field, so we provide one
     c.setopt(c.USERAGENT,'libcurl-agent/1.0')
     c.setopt(c.POSTFIELDS, postdata_str)
     # if we don't provide POSTFIELDSIZE, libcurl will strlen() by itself
     c.setopt(c.POSTFIELDSIZE, len(postdata_str))
     # Perform the request, res will get the return code
     c.perform()
     json = buf.getvalue()
     buf.close()
     c.close()
     return json

def parseJSON(n, spec_dB):
	global centerFreqs
	
        local_n = n
        #fout = open ("myFrequencies.csv", "w+") #FIXME 
        objs = json.loads(local_n)
        frequencyRanges = objs["result"]["spectrumSchedules"][0]["spectra"][0]["frequencyRanges"]
        nbr_frequencies = len(frequencyRanges)
	centerFreqs = []
        for i in range (0, nbr_frequencies):
		centerFreqs.append(0.5*(frequencyRanges[i]["startHz"] + frequencyRanges[i]["stopHz"]))
        #fout.close() #FIXME
	if (spec_dB == "google"): centerFreqs = [x / 1000000 for x in centerFreqs]
	print "There are ",nbr_frequencies, "frequencies available:", centerFreqs, "MHz"

def process(no_usrp, beacon_interv, spec_dB, remote_dB, source):
    global tb, word, centerFreqs, actualFreq, port, tun	
    global tun_device_filename, subp_ListenMaster
 	
    size 	  = 80    
    beacon        = "B" * 8
    terminate     = False

    #Opening socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # bind it
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    beacon = beacon + (size - len(beacon)) * " " 

    #Sending loop
    while not terminate:
	        time.sleep(float(beacon_interv))
		print "\nQuerying spectrum DB for available TV channels ..."
		n = getFreqMap(spec_dB, remote_dB)
	        parseJSON(n, spec_dB)
		print "Actual frequency: ", actualFreq/1e6, "MHz \n"
	        print "#######################################################################"
	        word = actualFreq
		if ((actualFreq / 1000000) not in centerFreqs) or (actualFreq < 400000000):
    			word = 1000000 * random.choice(centerFreqs)
			if (word < 400000000): print "Frequency chosen not supported with SBX daughterboard"
    			else: 
		        	actualFreq = word
    		        	# Need to handle the 6MHz channel BW assignement 
				if not no_usrp:
	    		        	newFreq = int(word)
	    		        	tb.set_freq(newFreq)
	    		        	print "\n\n\nSwitching to new Frequency: ", actualFreq / 1000000
		        	print "*********************************************************************"
		if source == "udp_sockets":
			print "\nBeacon sent: ", beacon
			s.sendto(beacon, ("localhost", int(port)))    
# /////////////////////////////////////////////////////////////////////////////
#                                   main
# /////////////////////////////////////////////////////////////////////////////

def main():
    global tb, usrp_addr, actualFreq, centerFreqs
    global getAck, word, port, subp_AssociateReq, n, VERBOSE, tun
    global subp_broadNewFreq, subp_periodListen, subp_slaveRespReq, tun_device_filename, subp_ListenMaster
	 
    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")

    # USRP/PHY related options
    parser.add_option("-u","--usrp-addr", default="addr = 192.168.10.2",
			   help="IP address of the USRP without \"addr=\"")
    parser.add_option("","--no-usrp", action="store_true", default=False,
			   help="Using file sink and source instead of USRPs")
    parser.add_option("-s", "--samp-rate",type="eng_float", default=4,
		           help="USRP sampling rate in MHz [default=%default]")
    parser.add_option("-g", "--gain",type="eng_float", default=0,
                           help="set the gain of the transceiver [default=%default]")
    parser.add_option("-f", "--init-freq", type="eng_float", default=485,
		           help="initial frequency in MHz [default=%default]")
    parser.add_option("", "--lo_offset", type="eng_float", default=0, metavar="Hz",
                           help="Local Oscillator frequency in MHz [default=%default]") 	
    parser.add_option("-o", "--otw", default="sc16",
		           help="select over the wire data format (sc16 or sc8) [default=%default]")
    parser.add_option("", "--encoding", type="choice", choices=['0','1','2','3','4','5','6','7'], default=0,
		           help="select the modulation/encoding scheme, [0,1,2,3,4,5,6,7]=\"BPSK 1/2\", \"BPSK 3/4\", \"QPSK 1/2\", \"QPSK 3/4\", \"16QAM 1/2\", \"16QAM 3/4\", \"64QAM 2/3\", \"64QAM 3/4\" [default=%default]")

    # MAC/Application related options 
    parser.add_option("-l", "--no-self-loop", action="store_true", default=False,
                           help="enable mechanism of avoiding self-routed packets [default=%default]")

    parser.add_option("", "--source", type="choice", choices=['udp_sockets', 'tuntap'], default='tuntap',
                           help="Use of either 'tuntap' interface or 'udp_sockets' [default=%default]")  
    parser.add_option("-B", "--beacon-interv", type="eng_float", default=1,
                           help="interval in sec between every beacon transmission [default=%default]")
    parser.add_option("-G", "--spec-dB", type="choice", choices=['local', 'google', 'remote'], default='google',
                           help="choice of the spectrum database: local dB (on port 5000!) or google dB or on remote host [default=%default]")
    parser.add_option("-a", "--remote-dB", default='pwct3.antd.nist.gov',
			   help="Adress of the remote host of the Spectrum Database, [default=%default]")
    parser.add_option("-y", "--bytes", type="eng_float", default=256,
                           help="Number of bytes to read/write from/to filedescriptors (for debug purpose) [default=%default]")
    parser.add_option("-i", "--interval", type="eng_float", default=0.2,
                           help="interval in seconds between two packets being sent [default=%default]")

    # Debugging and Verbose options	
    parser.add_option("", "--debug-MAC", action="store_true", default=False,
                           help="Debugging the MAC Layer [default=%default]")
    parser.add_option("-v", "--verbose",action="store_true", default=False, 
			   help="verbose mode [default=%default]")
   	
    (options, args) = parser.parse_args()

    getAck		= False
    VERBOSE 	    	= options.verbose
    usrp_addr       	= "addr="+options.usrp_addr
    initialFreq		= 1e6 * float(options.init_freq)

    tb = transceiverMaster(options.usrp_addr, options.no_usrp, options.samp_rate, options.lo_offset, options.encoding, options.otw, options.source, options.no_self_loop, options.debug_MAC)
    if not options.no_usrp:	
	tb.set_gain(options.gain)	
	tb.set_samp_rate(options.samp_rate*1e6)
        tb.set_freq(initialFreq)
        if VERBOSE:	
    	    print "usrp_addr = ", options.usrp_addr
	    print " \n Initial frequency: ", tb.get_freq()/1e6, "MHz"
	    print " Local Oscillator offset: ", tb.get_lo_offset()/1e6, "MHz \n"
    actualFreq = initialFreq	
    word = "FFFFFFFF"
    port = 52002

    subp_ListenMaster =  subprocess.Popen('./listenMaster.sh', shell=True) #FIXME
    if options.source == "tuntap":
	    try:
		subprocess.call("sudo ifconfig tap1 192.168.200.2", shell=True) #FIXME
	    except OSError as e:
		print "Execution failed: ", e
    #try :    
    #   #     subprocess.call("""sudo tunctl -d gr3 -f /dev/net/tun
    #   #                        sudo tunctl -t gr3 -u $USER -f /dev/net/tun 
    #                           sudo ip addr add 10.0.0.9/24 dev gr3
    #                           sudo ip link set gr3 up""", shell=True)
    #
    #except OSError as e:
    #        print >>sys.stderr, "Execution failed:", e

    threading.Timer(2, process, (options.no_usrp, options.beacon_interv, options.spec_dB, options.remote_dB, options.source)).start()	

     ## open the TUN/TAP interface
    #tun_fd = open_tun_interface("/dev/net/tun")

    #parent_conn, child_conn = Pipe()
    #tun = tunnel(child_conn.fileno(), tun_fd, VERBOSE, options.bytes, options.interval)
    #tun.start()
  	
    tb.Run(True) 

####################################
  	
#def open_tun_interface(tun_device_filename):
#            
#       	tun = os.open(tun_device_filename, os.O_RDWR)
#        return tun
#
#class tunnel(threading.Thread):
#
#    def __init__ (self, myPipe, tun_interface, verbose, bytes, interval):
#
#	threading.Thread.__init__(self)
#
#	self.verbose 	   = verbose 
#        self.tun_interface = tun_interface
#	self.bytes	   = bytes
#        self.interval	   = interval
#	
#	open("utils/listenMaster", "w+").close
#	self.fd = open("utils/listenMaster", 'r+b')
#	self.pipe_fd = myPipe
#         
#    def run(self) :
#	if self.verbose: print "Running the tunnel main function ..."
#        try :
#            #Opening socket
#  	    sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#            # bind it
#            sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
##             #Opening socket
##  	    udpSock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
##            # bind it
##            udpSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#  
#            while 1:
#	    	(inputready,outputready,exceptionready)= select.select([self.fd,self.pipe_fd],[],[])
#            	if self.fd in inputready :
#	    	    #payload = list(os.read(self.fd.fileno(), self.bytes))
#	            payload = os.read(self.fd.fileno(), self.bytes)
#	    	    if payload:
#			     print "payload at Master: ", payload	
#			     #payload = "".join(payload)	
#	    	             #if self.verbose: print "type(payload): ", type(payload)
#	    		     ip_header = payload[0:20]
#            		     (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
#			     #destIpAddr = str(socket.inet_ntoa(iph[9]))	
#	    	             if protocol == 1:
#				 if self.verbose: Packet.printIpHeader(payload)
#	    	    	 	 packet = payload  	
#	    	    	 	 icmp_type,icmp_code,icmp_identifier,icmp_sequence = Packet.unpackIcmpHeader(packet,iph_length)
#            		         # type 8 is echo request
#            		         if icmp_type == 8 : 
#            		             reply = Packet.createIcmpReply(packet)
#				     #if self.verbose: 
#					#print "got an echo request replying with echo response"
#		            		#Packet.printIpHeader(reply)
#	    		     	     #os.write(self.tun_interface, reply)
#	    	         	     destIpAddr = str(socket.inet_ntoa(iph[9]))
#	    	         	     srcIpAddr = str(socket.inet_ntoa(iph[8])) 	
#	    	         	     #if self.verbose: print "destIpAddr = str(socket.inet_ntoa(iph[9])) : ", destIpAddr			
#			     	 sendSock.sendto(reply, (destIpAddr, 55555))
#	      		     else:
#	    	          	 payload = 'E' + payload			
#				 ip_header = payload[0:20]
#                                 (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
#				 Packet.printIpHeader(payload)
#				 destIpAddr = str(socket.inet_ntoa(iph[9]))
#				 #os.write(self.tun_interface, payload) 	
#	    	     	     	 sendSock.sendto(payload, (destIpAddr, 5001))	
#				 #udpSock.sendto(payload, (destIpAddr, 5008))	
#		    time.sleep(self.interval)
##	    udpSock.close()
#            sendSock.close()
#        finally:
#            print "Exitting LOOP !!"

if __name__ == '__main__':
   try:
	main()		
   except KeyboardInterrupt:
	pass	

