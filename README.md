# Damn Web Scanner
Another web vulnerabilities scanner, this extension works on Chrome and Opera
The extension is working in the background and will notify you if it finds any vulnerability

Currently it scans for:
- SQL Injection
- Cross Site Scripting
- Local File Inclusion

**Warnings :** Do not use this extension for illegal purpose, the main goal of it is to simplify the life of bug hunters. It's a BETA version, many improvements will come don't worry

## New features
- Detect if the server is up
- Start/Stop button

## TODO
- Get vuln list in localstorage (list)
- ScanSQLTime/ScanSQLUnion
- Should detect and work with POST requests
- Export function for vulnerabilities
- Add some functions from https://sergeybelove.ru/one-button-scan/result/3004e0b978f19e58e3239087d119742779e1efbc/
- Deep and impact : args['url'],args['deep'],args['impact']
- Improve XSS vector - should work in JS context and onxxxx context: 
```
">><marquee><img src=x onerror=alert(1)></marquee>" ></textarea\></|\><details/open/ontoggle=confirm`1` ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->" ></script><sCrIpt>alert(1)</scRipt>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>\'"><svg onload=alert`1`><!--
```

## Install
You need to install and configure the server, it uses ghost and flask with gunicorn
```
pip install requests
pip install flask
pip install pyside
pip install ghost.py --pre
pip install gunicorn
sudo apt-get install gunicorn
```
If you have any trouble with Ghost you should have a look to the documentation : http://ghost-py.readthedocs.org/en/latest/

1 - The extension isn't packed, to use it go to chrome://extensions or opera://extensions then select "Load unpacked extension"
2 - Don't forget to launch the server
```
chmod +x ./launch
./launch
```
3 - Edit the server configuration in popup.js and background.js with your server's informations
```
var config_server = "http://127.0.0.1:8000";
```
4 - Browse the internet !