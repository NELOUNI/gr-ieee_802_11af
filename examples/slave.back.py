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
import os, sys, subprocess 
try:
	subprocess.call('ps -all | grep -ie \'listenSlave\' | awk \'{print $2}\' | xargs kill -9', shell=True) #FIXME ps -all or ps aux
													       #FIXME need to search for ncat, tee too ?	
except OSError as e:
    print >>sys.stderr, "Execution failed:", e

execfile("/home/naceur/.grc_gnuradio/wifi_phy_hier.py") #FIXME when calling this script using sudoEnv alias $USER = root, How to retrieve the calling user's home

from gnuradio import blocks, eng_notation, gr, uhd, digital
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.wxgui import forms
from grc_gnuradio import wxgui as grc_wxgui
from multiprocessing import  Pipe
from optparse import OptionParser
import signal, threading, pmt, time, wx, socket
import psutil,  string, random, struct, fcntl
import atexit, select
from fcntl import ioctl
#from mac import *
from packet import Packet
import ieee802_11, foo

#def open_tun_interface(tun_device_filename):
#    
#    mode = IFF_TAP | IFF_NO_PI
#    TUNSETIFF = 0x400454ca
#
#    tun = os.open(tun_device_filename, os.O_RDWR)
#    ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", "gr%d", mode))
#    ifname = ifs[:16].strip("\x00")
#    return (tun, ifname)

class broadcastScript():

    def __init__(self, myWord, myPort, mySlot, myInterval):
         self.myWord	= myWord
         self.myPort 	= myPort	
         self.mySlot	= mySlot
	 self.myInterval= myInterval
         size = 80 	   
         #Opening socket
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         # bind it
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
         #Sending loop
	 start_time = time.time()  # remember when we started
	 print "Data randomly sent to master: "
	 while (time.time() - start_time) < self.mySlot:
             #Adding timestamp and seq number to the data to be sent
             if (size > 0) :
                 #Filling the data with spaces until it reaches the requested size
                 self.myWord = self.myWord + (size - len(self.myWord)) * " "
             	 print self.myWord
             s.sendto(self.myWord, ("localhost", int(self.myPort)))	
             time.sleep(self.myInterval)
         s.close()

class transceiverSlave(grc_wxgui.top_block_gui):

    def __init__(self, addr, no_usrp, rate, lo_offset, encod, otw, source, no_self_loop, debug_MAC):
        grc_wxgui.top_block_gui.__init__(self, title="TransceiverSlave") #FIXME how to get rid of the gui

        ##################################################
        # Variables
        ##################################################
        self.addr         = addr
	self.no_usrp	  = no_usrp
	self.samp_rate	  = rate	
        self.otw          = otw 
        self.no_self_loop = no_self_loop    
	self.debug_MAC	  = debug_MAC
	self.lo_offset	  = lo_offset
        ##################################################
        # Blocks
        ##################################################
	if self.no_usrp:
                self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, self.samp_rate*1e6,True)
                ################################
                ## Using files instead of USRPs
                ###############################
                self.blocks_slaveFileSource = blocks.file_source(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/fileSinkMaster"), True)
                self.blocks_slaveFileSink   = blocks.file_sink(gr.sizeof_gr_complex*1, (os.getcwd()+"/utils/fileSinkSlave"), False)
                self.blocks_slaveFileSink.set_unbuffered(False)
                    
        else:
		############
		## source
		############
      		self.uhd_usrp_source_0 = uhd.usrp_source(",".join((self.addr, "")),
                                                         uhd.stream_args(cpu_format="fc32",
                                                                         otw_format=self.otw,
                                                                         channels=range(1),),)

                # TODO Explain the usage 
                self.uhd_usrp_source_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)

		#############
		## sink
		#############
	        self.uhd_usrp_sink_0 = uhd.usrp_sink(",".join((self.addr, "")),
			                            uhd.stream_args(cpu_format="fc32",
		                    				    otw_format=self.otw,
		                                                    channels=range(1),),"packet_len",)
 
                # TODO Explain the usage 
                self.uhd_usrp_sink_0.set_time_now(uhd.time_spec(time.time()), uhd.ALL_MBOARDS)

        # 802.11 a,g,p PHY Layer OFDM
        # Encoding choices=[0,1,2,3,4,5,6,7]="BPSK 1/2", "BPSK 3/4", "QPSK 1/2", "QPSK 3/4", "16QAM 1/2", "16QAM 3/4", "64QAM 2/3", "64QAM 3/4"
	print "Encoding Used: ", int(encod) #FIXME add the equivalent scheme
        self.PHY = wifi_phy_hier( encoding=int(encod), )

	# Foo block #TODO explain its usage
        self.foo_packet_pad2_0 = foo.packet_pad2(False, False, 0.001, 0, 10000) ## ?! ##
        (self.foo_packet_pad2_0).set_min_output_buffer(100000)

	# Multiply Const Block 
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc((0.38, )) #mult = 0.38
        (self.blocks_multiply_const_vxx_0).set_min_output_buffer(100000)

        # 802.11 a,g,p OFDM MAC Layer
	self.ieee802_11_ofdm_mac_0 = ieee802_11.ofdm_mac(([0x43, 0x43, 0x43, 0x43, 0x43, 0x43]), ([0x42, 0x42, 0x42, 0x42, 0x42, 0x42]), ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])) 

	# ofdm_parse_mac block for debugging purpose
        self.ieee802_11_ofdm_parse_mac_0 = ieee802_11.ofdm_parse_mac(False, False) 
        
        # Ethernet Encapsulation #TODO explain its usage 
        self.ieee802_11_ether_encap_0 = ieee802_11.ether_encap(True)

        # ///////////////////////////////////////////////////////////////////////////////////////////////////////
        #   Set virtual ethernet interface (tap0), relays packets between the interface and the GNU Radio PHY+MAC
        #   Use the Universal TUN/TAP device driver to move packets to/from kernel
        #   See /usr/src/linux/Documentation/networking/tuntap.txt
        # ///////////////////////////////////////////////////////////////////////////////////////////////////////
        if source == "tuntap":
                self.blocks_tuntap_pdu_0 = blocks.tuntap_pdu("tap0", 440, False)

        ##################################################
        # Asynch Message Connections
        ##################################################i

                self.msg_connect(self.ieee802_11_ether_encap_0, "to tap", self.blocks_tuntap_pdu_0, "pdus")
                self.msg_connect(self.blocks_tuntap_pdu_0, "pdus", self.ieee802_11_ether_encap_0, "from tap")

                self.msg_connect(self.ieee802_11_ether_encap_0, "to wifi", self.ieee802_11_ofdm_mac_0,    "app in")
                self.msg_connect(self.ieee802_11_ofdm_mac_0,    "app out", self.ieee802_11_ether_encap_0, "from wifi")

        else:   # UDP_Sockets 
		#TODO Test me ! 
                self.blocks_socket_pdu_0_Tx = blocks.socket_pdu("UDP_SERVER", "localhost", "52004", 10000)
                self.blocks_socket_pdu_0_Rx = blocks.socket_pdu("UDP_CLIENT", "localhost", "3333", 10000)

                self.msg_connect(self.ieee802_11_ofdm_mac_0, "app out", self.blocks_socket_pdu_0_Rx,      "pdus")
                self.msg_connect(self.blocks_socket_pdu_0_Tx, "pdus"  , self.ieee802_11_ofdm_mac_0,      "app in")

        ## Debugging at the MAC level To parse at the level of MAC ! Look at the flowgraph
        self.msg_connect(self.PHY,                   "mac_out", self.ieee802_11_ofdm_parse_mac_0, "in")   #TODO Test me !
        self.msg_connect(self.PHY,                   "mac_out", self.ieee802_11_ofdm_mac_0,      "phy in")
        self.msg_connect(self.ieee802_11_ofdm_mac_0, "phy out", self.PHY,                        "mac_in")

        ##################################################
        # Connections
        ##################################################

        if self.no_usrp:
		self.connect((self.PHY, 0), (self.blocks_multiply_const_vxx_0, 0)) 
	        self.connect((self.blocks_slaveFileSource, 0), (self.PHY, 0)) 
	        self.connect((self.foo_packet_pad2_0, 0), (self.blocks_slaveFileSink, 0)) 
	        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.foo_packet_pad2_0, 0)) 
        else:
		self.connect((self.PHY, 0), (self.blocks_multiply_const_vxx_0, 0)) 
	        self.connect((self.uhd_usrp_source_0, 0), (self.PHY, 0)) 
	        self.connect((self.foo_packet_pad2_0, 0), (self.uhd_usrp_sink_0, 0)) 
	        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.foo_packet_pad2_0, 0)) 

        if not self.lo_offset:
            self.lo_offset = self.samp_rate / 2.0 

        print "LO offset set to: ", self.lo_offset/1e6, "MHz"


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
	print "USRP Sink", r
	print "USRP Source", g	

    def set_samp_rate(self, rate):    
        self.rate = rate
        self.uhd_usrp_source_0.set_samp_rate(self.rate)
        self.uhd_usrp_sink_0.set_samp_rate(self.rate)

def generator(size=56, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def sync(no_usrp, tunnel, scan, dwell, slot, period, interval):

    global tb, gotSync, frequencies, i, Lines, actualFreq, tunName 
    global word, port, subp_listenSlave, tun

    data = generator()	
    gotSync = False
    if not no_usrp:
  	if (i == len(Lines)):
  	    print ("All available frequencies have been scanned. \n ...Looping again ")
  	    i = 1
	print "\n Trying frequency:", frequencies[i]/1e6, " MHz"
	tb.set_freq(frequencies[i]) 
	print " Re-tuned to:     ", tb.get_freq()/1e6, " MHz"
    with open("listenSlave", "r") as flistenSlave:	
          time.sleep(dwell)
          for line in flistenSlave:
                        if ('BBBBBBBB' in line):
                                print "\n \nSync done.....\nBegin Transmitting for 1 minute... "
                                gotSync = True
				actualFreq = frequencies[i]
    flistenSlave.close()
    i += 1
    if (gotSync == False):
        threading.Timer(scan,sync, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start()
    if (gotSync == True):
	print "ActualFreq = ", actualFreq, "\n"
	subp_listenSlave.kill()
	if (tunnel):	tun.run()
	else:		broadcastScript(generator(),port,slot, interval)
	threading.Timer(period, periodCheck, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start()	

def periodCheck(no_usrp, tunnel, scan, dwell, slot, period, interval):

   global i, port, tun

   subp_periodListen = subprocess.Popen("./listenSlave.sh")#,  shell=True) #FIXME
   gotBeacon = False	
   with open("listenSlave", "r") as flistenSlave:	
          time.sleep(dwell)
          for line in flistenSlave:
                        if ('BBBBBBBB' in line):
                                print "\n \nGot beacon...\nKeep trasmitting for another 1 minute...\n\n"
                                gotBeacon = True
				subp_periodListen.kill() 
   flistenSlave.close()	
   if gotBeacon:
	if (tunnel):	tun.run()
	else:		broadcastScript(generator(),port,slot, interval)
        threading.Timer(period,periodCheck, [no_usrp, tunnel, scan, dwell, slot, period, interval]).start() 
   else:
	i = 1	
	print "\n\nConnection Lost...\nSynching again...."	
	subp_periodListen.kill() 
	subp_listenSlave = subprocess.Popen("./listenSlave.sh")#,  shell=True) #FIXME
	threading.Timer(period,sync,[no_usrp, tunnel, scan, dwell, slot, period, interval]).start() 

# /////////////////////////////////////////////////////////////////////////////
#                                   main
# /////////////////////////////////////////////////////////////////////////////

def main():

    global tb, usrp_addr, gotSync, frequencies, i, Lines, tunName
    global word, port, p_listenSlave, subp_listenSlave, tun	

    parser = OptionParser(option_class=eng_option, usage="%prog: [options]") 

    # USRP/PHY related options
    parser.add_option("-u","--usrp-addr", default="192.168.10.2",
			   help="IP address of the USRP without \"addr=\"")
    parser.add_option("","--no-usrp", action="store_true", default=False,
                           help="Using file sink and source instead of USRPs")
    parser.add_option("-r", "--samp-rate", type="eng_float", default=4,
                           help="USRP sampling rate in MHz [default=%default]")
    parser.add_option("-o", "--otw", default="sc16",
                           help="select over the wire data format (sc16 or sc8) [default=%default]")
    parser.add_option("-g", "--gain", type="eng_float", default=0,
                           help="set the gain of the transceiver [default=%default]")
    parser.add_option("-f", "--init-freq", type="eng_float", default=650,
                           help="initial frequency in MHz [default=%default]")
    parser.add_option("", "--lo_offset", type="eng_float", default=0,
                           help="Local Oscillator frequency in MHz [default=%default]")
    parser.add_option("", "--encoding", type="choice", choices=['0','1','2','3','4','5','6','7'], default=0,
                           help="select the modulation/encoding scheme, [0,1,2,3,4,5,6,7]=\"BPSK 1/2\", \"BPSK 3/4\", \"QPSK 1/2\", \"QPSK 3/4\", \"16QAM 1/2\", \"16QAM 3/4\", \"64QAM 2/3\", \"64QAM 3/4\" [default=%default]")

    # MAC/Application related options
    parser.add_option("-l", "--no-self-loop", action="store_true", default=False,
                           help="enable mechanism of avoiding self-routed packets [default=%default]")

    parser.add_option("", "--source", type="choice", choices=['udp_sockets', 'tuntap'], default='tuntap',
                           help="Use of either 'tuntap' interface or 'udp sockets' [default=%default]") 
    parser.add_option("-t", "--tunnel",  action="store_true", default=False,
                       	   help="enable tunnel mode or send random data generated locally at slave node [default=%default]")
    parser.add_option("-S", "--scan-interv", type="eng_float", default=2,
                           help="interval in sec between every scan for frequency to sync with the master node [default=%default]")
    parser.add_option("-w", "--dwell", type="eng_float", default=2,
                           help="dwell time in each center frequency in the sync phase [default=%default]")
    parser.add_option("-p", "--period-check",type="eng_float", default=1,
                           help="interval in sec for period check of beacon [default=%default]")
    parser.add_option("-s", "--slot",type="eng_float", default=60,
                           help="duration in sec of the slave given slot to communicate data [default=%default]")
    parser.add_option("-i", "--interval", type="eng_float", default=1,
                           help="interval in seconds between two packets being sent [default=%default]")

    # Debugging options
    parser.add_option("", "--debug-MAC", action="store_true", default=False,  
                           help="Debugging the MAC Layer [default=%default]")
    parser.add_option("-v","--verbose", action="store_true", default=False,
			   help="verbose mode [default=%default]")

    (options, args) = parser.parse_args()
    usrp_addr	= "addr="+options.usrp_addr
    word = "FFFFFFFF"
    port = "52004"
    i = 1
    ffreqs = open('utils/freqs.csv')

    Lines = ffreqs.readlines()
    frequencies = [float(e.strip()) for e in Lines]
    ffreqs.close()
    open('listenSlave', 'w').close()

    tb = transceiverSlave(options.usrp_addr, options.no_usrp, options.samp_rate, options.lo_offset, options.encoding, options.otw, options.source, options.no_self_loop, options.debug_MAC)

    if not options.no_usrp:	
	tb.set_gain(options.gain)
	tb.set_samp_rate(options.samp_rate*1e6)
    	tb.set_freq(options.init_freq * 1e6) 
    	print "\n Initial frequency: ", tb.get_freq()/1e6, "MHz"

    subp_listenSlave = subprocess.Popen("./listenSlave.sh",  shell=True) #FIXME

    if options.source == "tuntap":
    	try:
    	    subprocess.call("sudo ifconfig tap0 192.168.200.1", shell=True) #FIXME
    	except OSError as e:
    	    print "Execution failed: ", e

   	
    ## Frequency Sweep procedure ##   	
    #threading.Timer(2,sync,[options.no_usrp, options.tunnel, options.scan_interv, options.dwell, options.slot, options.period_check, options.interval]).start()

    #if (options.tunnel):
    #    parent_conn, child_conn = Pipe()		
    #	tun = tunnel(tb.MAC, port, options.slot, child_conn.fileno(), options.interval, options.verbose)	
    #try:    
    #        subprocess.call("""sudo tunctl -d gr4 -f /dev/net/tun
    #                           sudo tunctl -t gr4 -u $USER -f /dev/net/tun 
    #                           sudo ip addr add 10.0.1.8/24 dev gr4
    #                           sudo ip link set gr4 up""", shell=True)
    #
    #except OSError as e:
    #        print >>sys.stderr, "Execution failed:", e
    tb.Run(True)

#class tunnel():
#
#    def __init__ (self, myMac, myPort, mySlot, myPipe, interval, verbose):
#
#	self.mac	= myMac
#        self.myPort 	= myPort	
#        self.mySlot 	= mySlot
#	self.pipe_fd	= myPipe
#	self.interval	= interval
#	self.verbose	= verbose
#
#        # open the TUN/TAP interface
#	(self.tun_fd, self.tun_ifname) = open_tun_interface("/dev/net/tun")
#
#        subprocess.call('sudo ifconfig ' + self.tun_ifname + ' 192.168.200.1', shell=True)
#	
#    def run(self) :
#	if self.verbose: print "Running the tunnel main function ..."
#        try :
#	    listen = subprocess.Popen("./listenSlave.sh")
#	    try:
#	    	sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#		# bind it
#	        sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#	    except socket.error , msg:
#	    	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
#	    	sys.exit()
#
#	    #Sending loop
#            start_time = time.time()  
#            while (time.time() - start_time) < self.mySlot:
#		print "Testing 385"
#		payload = os.read(self.tun_fd, 128)
#		print "\n os.read(self.tun_fd, 128) ......    ", sys.stdout.write(payload), "\n"
#		(inputready,outputready,exceptionready)= select.select([self.tun_fd,self.pipe_fd],[],[])
#		print "Testing 373"
#                if self.tun_fd in inputready :
#		    print "Testing 379"
#		    if self.verbose: Packet.printIpHeader(payload)
#                    ip_header = payload[0:20]
#                    (iph, protocol,iph_length,ip_length, src_ip,dst_ip) = Packet.unpackIpHeader(ip_header)
#
#                    if protocol == 1: #deal with ICMP echo request
#			print "protocol == 1"	
#                        packet = payload
#                        icmp_type,icmp_code,icmp_identifier,icmp_sequence = Packet.unpackIcmpHeader(packet,iph_length)
#                        if icmp_type == 8 : # type 8 is echo request
#                            reply = Packet.createIcmpReply(packet)
#			    if self.verbose: 
#				#print "got an echo request replying with echo response"
#                            	Packet.printIpHeader(reply)
#                        #os.write(self.tun_fd,reply) 
#			self.mac.app_in(pmt.cons(pmt.PMT_NIL, pmt.to_pmt(packet)))
#		   
#                    else:
#			print "Testing 401"
#			if self.verbose: print "Not an ICMP Packet"
#			bytes = map(ord,payload)
#			print "bytes @ 398", bytes
#			self.mac.app_in(pmt.cons(pmt.PMT_NIL, pmt.to_pmt(bytes)))
#			print "\n \n Passed 411"
#
#                elif self.pipe_fd in inputready:
#		    print "self.pipe_fd in inputready"	
#                    payload = os.read(self.pipe_fd, 256)
#                    nwritten = os.write(self.tun_fd,payload)
#                    if self.verbose: print " tunnel.run: write nbytes ", nwritten
#                time.sleep(self.interval)
#	    print "Testing 412"	
#            listen.kill()
#  	    sendSock.close()
#
#        finally:
#            print "Exitting LOOP !!"

if __name__ == '__main__':
   try:
        main()
   except KeyboardInterrupt:
	os.remove(listenSlave)
        sys.exit(0)

