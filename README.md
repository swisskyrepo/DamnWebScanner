# Damn Web Scanner
Another web vulnerabilities scanner, this extension works on Chrome and Opera
The extension is working on the background and will notify you if it finds any vulnerability

Currently it scans for:
- SQL Injection
- Cross Site Scripting
- Local File Inclusion

**Warnings :** Do not use this extension for illegal purpose, the main goal of it is to simplify the life of bug hunters. It's a **BETA version**, many improvements will come don't worry

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
4 - Browse the internet ! (Don't forget to start the extension by clicking the 'START' button)

## New features
- Detect if the server is up
- Start/Stop button
- New XSS vectors, work in different contexts (JS var, JS function, inside HTML tag, outside HTML tag)
- Basic page to list the vulnerabilities URL and TYPE
- Time based SQLi scanner using polyglot vectors (MySQL, SQLite, Oracle, Postgresql, SQL Server)
- New logo for the extension

## TODO - Work in progress
- Should detect target in source code.. (list of targets, then launch scan)
- Should detect and work with POST requests
- Export function for vulnerabilities
- Deep and impact : args['url'],args['deep'],args['impact']
- Launch scan when a button is clicked/ form submitted / page opened via URL - chrome.tabs.onActivated.addListener
- Cookies and User Agent in server request
- BUG multiples vulns not added

## Thanks
- Polyglot vector for SQL injections [The Ultimate SQL Injection Payload](https://labs.detectify.com/2013/05/29/the-ultimate-sql-injection-payload/)
- Polyglot vector for XSS injection 1 [One vector to rule them all](http://www.thespanner.co.uk/2010/09/15/one-vector-to-rule-them-all/)
- Polyglot vector for XSS injection 2 [Unleashing an Ultimate XSS Polyglot](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)