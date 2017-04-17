# USRP/GNU Radio Based IEEE 802.11af Implementation 

This is an IEEE 802.11af O-QPSK transceiver for GNU Radio v3.7. It is based on the UCLA implementation (https://cgran.org/wiki/UCLAZigBee) of Thomas Schmid.

# Features

Currently, it features the following:

- The O-QPSK PHY encapsulated in a hierarchical block.
- A block that implements the Rime communication stack. Rime is a lightweight communication stack designed for Wireless Sensor Networks and is part of the Contiki Operating System.
- A transceiver flow graph with USRP <-> PHY <-> MAC <-> Network layer (Rime) <-> UDP Socket / APP which resembles pretty well the ISO/OSI structure.
- A sample application which visualizes sensor values. The application shows how easy it is to connect an external program to the flow graph by using Socket PDU blocks.

Some interesting properties:
- Packets can be piped to Wireshark.
- The complete physical modulation is done with plain GNU Radio blocks.
- It is interoperable with TelosB sensor motes.
- It is interoperable with Contiki.
- It uses a block to tag packet bursts with tx_sob and tx_eob tags. This tags are understood by the UHD blocks and allow fast switching between transmission and reception.

# Dependencies

Please note that ```apt-get``` is the package manager of Debian/Ubuntu based systems, while ```port``` is one package manager for OSX. So use either (not both) according to your needs.

### gr-ieee-802-11agp
	https://github.com/bastibl/gr-ieee802-11.git (depends on: gr-foo, log4cpp, itpp)

### dpkt
	https://code.google.com/p/dpkt/downloads/list

### psutil
	https://pypi.python.org/pypi/psutil#downloads 

### iperf/jperf 
	https://code.google.com/p/xjperf/

### flask
	 http://flask.pocoo.org/
	
### json 

### nmap 
	ncat command

# Installation

## From Source
2. Build and install gr-ieee-802-11af in your GNU Radio installation.
	$ cd gr-ieee_802_11af
	$ mkdir build
	$ cd build
	$ cmake [optional switches] ../
	$ make && make test
	$ sudo make install
    	$ sudo ldconfig

## Using PyBOMBS

# Checking you installation

## Troubleshooting

# Usage

If using ssh and a normal user user want to run the GUI "main_GUI.py" using sudo, first make sure to allow X11 authentication:
	sudo xauth add $(xauth -f ~/.Xauthority list|tail -1)


* Tested with GNU Radio 3.7.6 and Python 2.6 and 2.7.

## Testing with iperf/jperf

Virtual ethernet interfaces (tap0 for slave, tap1 for master), relays packets between the interfaces
and the GNU Radio PHY+MAC. Use the Universal TUN/TAP device driver to move packets to/from kernel
See /usr/src/linux/Documentation/networking/tuntap.txt

Measuring the Master/Slave throughput in the context of secondaries vacating the chanel for the Primary,

Run the master.py and slave.py, one on each machine. 
sudo rights are needed, to create the virtual interface, configure, turn it up and create raw socket to test the flow of data over the link.

## Command Line Options

### tvClient.py:

### webServerWSDB.py:

### Master/Slave common options:

### masterTunnel.py:

### slaveTunnel.py:

# Troubleshooting

# Asking for help

# Known Bugs

# Disclaimers

# Future Work
