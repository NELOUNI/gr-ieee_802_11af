from flask import Flask, request, render_template, flash, session, url_for, redirect
import json, StringIO, time, datetime, os, shutil, errno 
from gnuradio import eng_notation
from gnuradio.eng_option import eng_option
from optparse import OptionParser

app = Flask(__name__)

# Load default config and override config from an environment variable
app.config.update(dict(
    DEBUG=True,
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))

app.config.from_envvar('FLASKR_SETTINGS', silent=True)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid password'
        else:   
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('update'))
    return render_template('login.html', error=error)

def copyanything(src, dst):
    try:
        shutil.copytree(src, dst)
    except OSError as exc: # python >2.5
        if exc.errno == errno.ENOTDIR:
            shutil.copy(src, dst)
        else: raise

def init_db():
    """Creates the database tables."""
    copyanything('spectrumdB.back','spectrumdB')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('update'))

@app.route('/', methods = ['POST'])
def main():
  global availableFreqs
  global usedFreqs

  availableFreqs = ''
  usedFreqs = ''
  
  fspectrumdB = open("spectrumdB", )
  for i, line in enumerate(fspectrumdB):
    if i == 0:
       availableFreqs = (line.split(": ")[1:][0]).split()
    elif i == 1:
       usedFreqs = (line.split(": ")[1:][0]).split()	
       break	
  fspectrumdB.close()

  if 'usedFreq:' in request.data:
      used = request.data.strip('usedFreq: ')
      print "used: ", used 	
      fspectrumdB        = open("spectrumdB", "r+")
      fupdatedSpectrumdB = open("updatedSpectrumdB", "w+")	 
      for i, line in enumerate(fspectrumdB):
    	  if i == 0:
	     if used in line:
		 fupdatedSpectrumdB.write(line.replace(used,''))
             else:
	     	 fupdatedSpectrumdB.write(line)	
    	  elif i == 1:
             if used in line:
		 line.replace(used,'')		
	     	 fupdatedSpectrumdB.write(line)	
	     else:	 	
	         fupdatedSpectrumdB.write(''.join([line.strip('\n'), " ", used]))
      fspectrumdB.close()
      fupdatedSpectrumdB.close()	    
      os.rename('updatedSpectrumdB','spectrumdB')
      return redirect(url_for('update'))

  elif 'jsonrpc' in request.data:
      objs = json.loads(request.data)  
      devDesc = objs["params"]["deviceDesc"]
      DUMPS = {
        "jsonrpc": objs["jsonrpc"], 
      	"id":  objs["id"],	
      	"result":{
      		  "kind": "spectrum#pawsGetSpectrumResponse", 
                        "type": objs["params"]["type"],
      		  "version": objs["params"]["version"],
                        "timestamp": time.time(),                     # FIXME need to be compliant with PAWS: #YYYY-MMDDThh: mm:ssZ, as defined by 
                                                                      # Date and Time on the Internet: Timestamps [RFC3339]
      		  "deviceDesc":{
      				"serialNumber":devDesc["serialNumber"], 
      				"fccId":devDesc["fccId"], 
      				"fccTvbdDeviceType":devDesc["fccTvbdDeviceType"]
      			       },
      		  "spectrumSchedules":[{
      					"eventTime":{
      						     "startTime":"startTime",
      						     "stopTime":"stopTime"
      						    },
      					"spectra":[{
      						    "bandwidth": 6000000.0,
      						    "frequencyRanges":
								      [{"startHz": float(available) - 3.0, 
									"stopHz": float(available) + 3.0, 
									"maxPowerDBm": -25} for available in availableFreqs]
                                                  }]
      				       }],
      		  "needsSpectrumReport": False,
      		  "rulesetInfo": {
      				 "authority": "US",
      				 "maxLocationChange": 100.0,
      				 "maxPollingSecs": 86400,
      				 "rulesetIds": ["FccTvBandWhiteSpace-2010"]
      				}
                		  }
      	}
      print "\n", json.dumps(DUMPS, sort_keys = True, indent = 4, separators=(',', ': ')) , "\n"
      return (json.dumps(DUMPS, sort_keys = True, indent = 4, separators=(',', ': ')))

  else:
     if (request.form['availableFreq'] != ''):
        fupdatedSpectrumdB = open("updatedSpectrumdB", "w+")
        fspectrumdB = open("spectrumdB", "r+")
	if request.form['availableFreq'] in availableFreqs:
		pass
	else:
		if request.form['availableFreq'] in usedFreqs:
			usedFreqs.remove(request.form['availableFreq'])
		availableFreqs.append(request.form['availableFreq'])	  	
	fupdatedSpectrumdB.write(''.join(["AvailableFreqs: ", " ".join(str(a) for a in availableFreqs),'\n']))
	fupdatedSpectrumdB.write(''.join(["UsedFreqs: ", " ".join(str(u) for u in usedFreqs)]))	
	fspectrumdB.close()
     	fupdatedSpectrumdB.close()           
	os.rename('updatedSpectrumdB','spectrumdB')

     elif (request.form['usedFreq'] != ''):
	fupdatedSpectrumdB = open("updatedSpectrumdB", "w+")
        fspectrumdB = open("spectrumdB", "r+")
	if request.form['usedFreq'] in usedFreqs :
		pass
	else:
		if request.form['usedFreq'] in availableFreqs:
			availableFreqs.remove(request.form['usedFreq'])
		usedFreqs.append(request.form['usedFreq'])
	fupdatedSpectrumdB.write(''.join(["AvailableFreqs: ", " ".join(str(a) for a in availableFreqs),'\n']))
	fupdatedSpectrumdB.write(''.join(["UsedFreqs: ", " ".join(str(u) for u in usedFreqs)]))
     	fspectrumdB.close()
     	fupdatedSpectrumdB.close()           
        os.rename('updatedSpectrumdB','spectrumdB')
     return redirect(url_for('update'))

@app.route('/')
def update():
  global availableFreqs
  global usedFreqs	
  availableFreqs = ''
  usedFreqs = ''
 	
  fspectrumdB = open("spectrumdB")
  for i, line in enumerate(fspectrumdB):
    if i == 0:
       availableFreqs = (line.split(": ")[1:][0]).split()
    elif i == 1:
       usedFreqs = (line.split(": ")[1:][0]).split()	
  fspectrumdB.close()
  return render_template('main.html', myAvailable=availableFreqs , myUsed=usedFreqs)

if __name__ == '__main__':

    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")
    parser.add_option("-p","--port", type="int", default=5000)
    parser.add_option("-s","--ssl", action="store_true", default=False,
                           help="Use of SSL Encryption")
    (options, args) = parser.parse_args()

    init_db()
    if not options.ssl:
	print "Running without SSL Encryption"
        app.run(host='0.0.0.0', port=options.port)
    else:
	print "Running with SSL Encryption"
        from OpenSSL import SSL
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.use_privatekey_file('../utils/keys/rsa.key')
        context.use_certificate_file('../utils/keys/rsa.crt')
        app.run(host='0.0.0.0', port=options.port, ssl_context=context)

