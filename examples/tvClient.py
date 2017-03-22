import subprocess, os, sys, platform
try:
	subprocess.call("ps aux | grep nae | grep -e 'tx_samples_from_file' | awk '{print $2}' | xargs kill -9")
except OSError as e:
	print >>sys.stderr, "Execution failed", e
sys.path.append("./WSDB")
import signal, atexit, time
from gnuradio.eng_option import eng_option
import webServerWSDB
from webServerWSDB import app
import json, pycurl, StringIO
from optparse import OptionParser

if __name__ == '__main__':      

        ctx = app.app_context()
        ctx.push()      

        parser = OptionParser(option_class=eng_option, usage="%prog: [options]")
        parser.add_option("-u","--usrp-addr"       , default="addr=172.16.19.2", help="[default=%default]")
        parser.add_option("-f","--center_frequency", default=None, help="[default=%default]")
        parser.add_option("-g","--gain"            , default=10, help="[default=%default]")
        parser.add_option("-B","--no-dB-update"    , action="store_true", default=False, help="Do not update the local spectrum database [default=%default]")
        parser.add_option("-v","--verbose"         , action="store_true", default=False, help="[default=%default]")
	parser.add_option("-d","--uhd-dir"         , default=os.getenv("HOME")+"/uhd", help="installation directory of uhd, [default=%default]")
        parser.add_option("-c","--video"           , help="location of the video to play back, [default=%default]", default=None)
        parser.add_option("-p","--port"            , help="port number to post to webServer, [default=%default]", default=5000)
        parser.add_option("-W","--web-server"      , help="webServer address, [default=%default]", default="127.0.0.1")
        parser.add_option("-s","--samp-rate"       , type="eng_float",   help="sample rate in MHz at which to play back the video, [default=%default]", default=6.25)

        (options, args) = parser.parse_args()
        freq = 1000000 * int(options.center_frequency)
        gain = options.gain
        rate = 1000000 * options.samp_rate          


        buf = StringIO.StringIO()
        postdata_str = "usedFreq: " + str(options.center_frequency)
        if options.verbose: print "postdata_str: ", postdata_str
        c = pycurl.Curl()

	c.setopt(pycurl.SSL_VERIFYPEER, 1)
	c.setopt(pycurl.SSL_VERIFYHOST, 2)
	c.setopt(pycurl.CAINFO, "utils/keys/rsa.crt")

        c.setopt(c.HTTPHEADER, ['Accept: application/json', 'Content-Type: application/json','charsets: utf-8'])
        c.setopt(c.URL, 'https://'+ options.web_server + ':'+str(options.port))
        # send all data to this function
        c.setopt(c.WRITEFUNCTION, buf.write)
        # some servers don't like requests that are made without a user-agent field, so we provide one
        c.setopt(c.USERAGENT,'libcurl-agent/1.0')
        c.setopt(c.POSTFIELDS, postdata_str)
        # if we don't provide POSTFIELDSIZE, libcurl will strlen() by itself
        c.setopt(c.POSTFIELDSIZE, len(postdata_str))
        if options.verbose: c.setopt(c.VERBOSE, 1) #c.setopt(c.DEBUGFUNCTION, test)
        if (not options.no_dB_update):
                c.perform()
        #print c.getinfo(pycurl.HTTP_CODE) , c.getinfo(pycurl.EFFECTIVE_URL)
        if options.verbose: 
                            json = buf.getvalue()
                            buf.close()
                            print json
        c.close()
	try:
	    if os.path.isdir(options.uhd_dir+'/lib'):
            	subprocess.call(options.uhd_dir+'/lib/uhd/examples/tx_samples_from_file --args ' + options.usrp_addr + ' --file ' + options.video + ' --type short --rate ' + str(rate) + ' --gain 0 --freq ' + str(freq) + ' --repeat ', shell=True)	
	    else: 
	    	subprocess.call(options.uhd_dir+'/lib64/uhd/examples/tx_samples_from_file --args ' + options.usrp_addr + ' --file ' + options.video + ' --type short --rate ' + str(rate) + ' --gain 0 --freq ' + str(freq) + ' --repeat ', shell=True)
	except OSError as e:
            print >>sys.stderr, "Execution failed", e
        ctx.pop()

