###!/usr/bin/env python
##################################################
# Gnuradio Python Flow Graph
# Title: TransceiverSlave
# Generated: Tue Feb 11 16:36:42 2014
##################################################

# Copyright 2005,2006,2011 Free Software Foundation, Inc.
# 
# This file is part of GNU Radio
# 
# GNU Radio is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2, or (at your option)
# any later version.
# 
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with GNU Radio see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

from gnuradio import gr
import pmt, time, socket
import subprocess, os, sys, string, random

class mac(gr.sync_block): 
  def __init__(self, debug, no_self_loop):
	global d_msg_len, d_mac_id, d_seq_nr, d_msg

        gr.sync_block.__init__(
		               self,
		               name = "mac",
		               in_sig = None,
		               out_sig = None
			      )

	self.debug   		= debug 
	self.no_self_loop	= no_self_loop 
	d_seq_nr     		= 0
	d_mac_id		= 0	
        d_msg			= []
	d_msg_len		= 0

	if self.no_self_loop:
		random.seed(os.getpid())	    	
		d_mac_id = random.randint(1, 100)     	   	
	self.message_port_register_in(pmt.intern('phy in'))
        self.set_msg_handler(pmt.intern('phy in'), self.phy_in)

	self.message_port_register_in(pmt.intern('app in'))
        self.set_msg_handler(pmt.intern('app in'), self.app_in)

	self.message_port_register_out(pmt.intern('app out'))
	self.message_port_register_out(pmt.intern('phy out'))

  def phy_in(self, msg): # consume messages
	global d_mac_id

	if self.debug: print "****************************** \nConsuming messages...\n******************************** "
	data = 0
	if(pmt.is_eof_object(msg)):
                self.message_port_pub(pmt.intern('phy out'), pmt.PMT_EOF)
		return
	elif(pmt.is_pair(msg)): 
		#if self.debug: print  "pmt_is_pair" 
		data = pmt.cdr(msg)					
	elif(pmt.is_bool(msg)):
                if self.debug: print  "mac.py:phy in: got a busy notification" 
		return
	data_len = pmt.length(data) 
	if self.debug:
		print ""
		print "Data received from Physical Layer: ", pmt.u8vector_elements(data)
		print ""	
	if (data_len < 13): 
		if self.debug: 	print  "MAC: frame too short. Dropping! \n"
		return
	else: 
       		if self.no_self_loop:    # Compare to our own "mac ID" and reject if we are self routing packets.
 		    macId = pmt.u8vector_elements(data)[0]   
		    if self.debug: 	
		    	print "macId of the packet: ", macId 	
		    	print "our macId: 	    ", d_mac_id 
		    	print "data_len: ", data_len
		    if (macId != d_mac_id): 
			    crc = crc16(pmt.u8vector_elements(data), data_len) 
			    if self.debug: print  "#### CRC at Reception: #### " , crc.get_crc(), "\n"
			    if (crc.get_crc()):
	        		    print  "MAC: wrong crc. Dropping packet! \n" 
				    return	
			    macPayload = pmt.make_u8vector(data_len - 13, 0)
			    #Because of the iperf 'E' issue	
			    #macPayload = pmt.make_u8vector(data_len - 14, 0)
			    #for i in range(data_len - 14):	
			    for i in range(data_len - 13):			    
				    pmt.u8vector_set(macPayload, i, pmt.u8vector_elements(data)[i+11]) 	
			    self.message_port_pub(pmt.intern('app out'), pmt.cons(pmt.PMT_NIL, macPayload))
			    if self.debug: print "Data sent up to Application Layer : ", pmt.u8vector_elements(macPayload), "\n"	
		else:
		    crc = crc16(pmt.u8vector_elements(data), data_len) 
		    if self.debug: print  "#### CRC at Reception: #### " , crc.get_crc(), "\n"
		    if(crc.get_crc()):
        		    if self.debug: print  "MAC: wrong crc. Dropping packet! \n" 
			    return	

		    macPayload = pmt.make_u8vector(data_len - 14, 0)
		    for i in range(data_len - 14):	
			    pmt.u8vector_set(macPayload, i, pmt.u8vector_elements(data)[i+10]) 	
		    self.message_port_pub(pmt.intern('app out'), pmt.cons(pmt.PMT_NIL, macPayload))
		    if self.debug: print "Data sent up to Application Layer : ", pmt.u8vector_elements(macPayload), "\n"	


  def app_in(self, msg): # Generate messages
	global d_msg_len, d_mac_id, d_seq_nr, d_msg

	if self.debug: 
		print "******************************** \nGenerating messages ...\n******************************** "
		print ""
		#print "MAC:app_in: got something:", msg
	data = msg

        if(pmt.is_pair(msg)):
                data = pmt.cdr(msg)
                #if self.debug: print  "mac.py:app_in: pmt_is_pair \n" 
        elif(pmt.is_eof_object(msg)):
                if self.debug: print  "MAC: exiting" 
		return
        elif(pmt.is_blob(msg)):
		 data = pmt.cdr(msg)
		 if self.debug: print "data is blob" 	
	else:
		if self.debug: print  "MAC: unknown input" 
		return
	if pmt.is_u8vector(data):
		"data is u8vector"		
		data_elements = pmt.u8vector_elements(data) 
		if self.debug:
			print "Data from Application Layer: ", data_elements, "\n"
			print "Data length :", len(data_elements), "\n"

	d_msg = []

	if pmt.is_symbol(data):
		dataString = pmt.symbol_to_string(data)
		if self.debug:	print "len(pmt.symbol_to_string(data)): ",len(dataString), "pmt.symbol_to_string(data): ", dataString
		generate_mac(data, len(dataString), self.debug, d_mac_id, d_seq_nr, self.no_self_loop)
	else:
		generate_mac(data, pmt.length(data), self.debug, d_mac_id, d_seq_nr, self.no_self_loop)

	generatedMacPayload = pmt.make_u8vector(len(d_msg), 0)
	for i in range(len(d_msg)):
	    #if (pmt.is_vector(data)): 
	        #print "d_msg[",i,"]: ", d_msg[i], " ; type: ", type(d_msg[i])
	    #    pmt.vector_set(generatedMacPayload, i, pmt.to_pmt(d_msg[i]))
	    pmt.u8vector_set(generatedMacPayload, i, d_msg[i]) 	
	    #else: pmt.u8vector_set(generatedMacPayload, i, d_msg[i]) 	

	self.message_port_pub(pmt.intern("phy out"), pmt.cons(pmt.PMT_NIL, generatedMacPayload))
	#Print 
	#Print "**********************************"
	#Print
	if self.debug:	print "Data Published to physical Layer: ", pmt.u8vector_elements(generatedMacPayload), "\n"	
	
class crc16:
  def __init__(self, buf, len):
	self.crc = 0
	for i in range (len):
		for k in range(8):
			input_bit = (not not(int(buf[i]) & (1 << k))) ^ (self.crc & 1) 
			self.crc = self.crc >> 1
			if(input_bit): 
				self.crc ^= (1 << 15)
				self.crc ^= (1 << 10)
				self.crc ^= (1 <<  3)
  def get_crc(self):
	return self.crc
    
class generate_mac:
  def __init__(self, buf, len, debug, d_mac_id, d_seq_nr, no_self_loop): 

	self.debug 	= debug
	self.buf   	= buf
        self.len   	= len
	self.d_seq_nr	= d_seq_nr
	self.d_mac_id	= d_mac_id
	self.no_self_loop  = no_self_loop

	if self.no_self_loop:
	        #Insert an id here to check for self routing. This makes the packet non standard.
	        d_msg.insert(0, self.d_mac_id)	
		d_msg.insert(1, 11 + self.len + 2) 

		#FCF
		d_msg.insert(2,0x41)
		d_msg.insert(3,0x88)

		#seq nr
		d_msg.insert(4,++self.d_seq_nr)

		#addr info
		d_msg.insert(5,0xcd)
		d_msg.insert(6,0xab)
		d_msg.insert(7,0xff)
		d_msg.insert(8,0xff)
		d_msg.insert(9,0x40)
		d_msg.insert(10,0xe8)
	        #Copy the data here.
		if (pmt.is_vector(buf)): 
			for i in range(pmt.length(buf)):	
				d_msg.insert(10+i,pmt.to_long(pmt.vector_ref(buf,i)))
		elif (pmt.is_uniform_vector(buf)):
			d_msg.extend(pmt.u8vector_elements(buf))	
		else:
			bufString = pmt.symbol_to_string(buf)
			#print "pmt.symbol_to_string(buf): ", bufString
			#print "pmt.length(buf): ", pmt.length(buf)
			bytes = map(ord,bufString)
			#print "map(ord,buf): ", bytes
			d_msg.extend(bytes)

	        #Compute the CRC over the whole packet (excluding the CRC bytes themselves)
		crc = crc16(d_msg, self.len + 11) 
	        #if self.debug: print  "#### CRC at Transmission: #### ", crc.get_crc() 
       
       		#CRC goes on the end.
		d_msg.insert(11+ self.len, crc.get_crc() & 0xFF)
		d_msg.insert(12+ self.len, crc.get_crc() >> 8)

		d_msg_len = 11  + self.len + 2
		print 
		print
		if self.debug: print "d_msg: ", d_msg
		print
		print
	else:
	        #Preamble length + CRC length ( CRC at the end)
		d_msg.insert(0, 10 + self.len  + 2)

		#FCF
		d_msg.insert(1,0x41)
		d_msg.insert(2,0x88)

		#seq nr
		d_msg.insert(3,++self.d_seq_nr)

		#addr info
		d_msg.insert(4,0xcd)
		d_msg.insert(5,0xab)
		d_msg.insert(6,0xff)
		d_msg.insert(7,0xff)
		d_msg.insert(8,0x40)
		d_msg.insert(9,0xe8)

	        #Copy the data here.
		d_msg.extend(pmt.u8vector_elements(buf))
	        #Compute the CRC over the whole packet (excluding the CRC bytes themselves)
	        crc = crc16(d_msg, self.len + 10)
		if self.debug: print  "#### CRC at Transmission: #### ", crc.get_crc() 

		d_msg.insert(10 + self.len, crc.get_crc() & 0xFF)
		d_msg.insert(11 + self.len, crc.get_crc() >> 8)

	        d_msg_len = 10  + self.len + 2 # Preamble + Data + CRC

	if self.debug: print  " msg len ", d_msg_len, " len ", self.len, "\n"

