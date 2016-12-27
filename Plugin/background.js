var config_server = "http://127.0.0.1:8000";

/**
 * Extract the domain from an URL
 * @param string(url) - url of the target which will be shorten	
 */
function extract_domain(url){
    var domain;
    if (url.indexOf("://") > -1) {
        domain = url.split('/')[2];
    }
    else {
        domain = url.split('/')[0];
    }

    //find & remove port number
    return domain.split(':')[0];
}

/**
 * Inspect the source code and send a request to the server for every url
 *
 * @param string(url)    - url of the target
 * @param string(deep)   - deep of the target, 0 is the actual page
 * @param string(impact) - aggressivity of the scan from 0 to 5
 *
 */
function send_target(server, url, deep, impact){
    var http = new XMLHttpRequest();
    infos = server + "/?url=" + url + "&deep="+ deep + "&impact=" + impact

    // Display the informations sent by the scanner
    http.onreadystatechange = function() {
      if (http.readyState == XMLHttpRequest.DONE) {
        http_data = JSON.parse(http.responseText);
        console.log(http.responseText);

        // Notifications and update local storage
        if (http_data.xss != '0'){

          // Update XSS count
		      chrome.storage.sync.get(['xss'], function(items) {
            chrome.storage.sync.set({'xss': items['xss']+parseInt(http_data.xss)})
          });

          // Update vulnerabilities URL list
          chrome.storage.sync.get(['list'], function(items) {
            chrome.storage.sync.set({'list': items['list']+http_data.list})
          });

          new Notification('New vulnerability detected !', {
            icon: 'icon.png',
            body: 'XSS on '+extract_domain(unescape(url))
          })();  
        }

        if (http_data.sql != '0'){

          // Update SQL count
          chrome.storage.sync.get(['sql'], function(items) {
            chrome.storage.sync.set({'sql': items['sql']+parseInt(http_data.sql)})
          });

          // Update vulnerabilities URL list
          chrome.storage.sync.get(['list'], function(items) {
            chrome.storage.sync.set({'list': items['list']+http_data.list})
          });

          new Notification('New vulnerability detected !', {
            icon: 'icon.png',
            body: 'SQLi on '+extract_domain(unescape(url))
          })();
        }

        if (http_data.lfi != '0'){
          // Update LFI count
          chrome.storage.sync.get(['lfi'], function(items) {
            chrome.storage.sync.set({'lfi': items['lfi']+parseInt(http_data.lfi)})
          });

          // Update vulnerabilities URL list
          chrome.storage.sync.get(['list'], function(items) {
            chrome.storage.sync.set({'list': items['list']+http_data.list})
          });

          new Notification('New vulnerability detected !', {
            icon: 'icon.png',
            body: 'LFI on '+extract_domain(unescape(url))
          })();
        }

        if (http_data.rce != '0'){
          // Update RCE count
          chrome.storage.sync.get(['rce'], function(items) {
            chrome.storage.sync.set({'rce': items['rce']+parseInt(http_data.rce)})
          });

          // Update vulnerabilities URL list
          chrome.storage.sync.get(['list'], function(items) {
            chrome.storage.sync.set({'list': items['list']+http_data.list})
          });

          new Notification('New vulnerability detected !', {
            icon: 'icon.png',
            body: 'RCE on '+extract_domain(unescape(url))
          })();
        }

      }
    }
    http.open("GET", infos, true);
    http.send();
}

// Set a clean local storage
chrome.storage.sync.set({'rce':0, 'xss': 0, 'sql': 0, 'lfi': 0, 'work': 0, 'list':'' })

// Launch a scan when the tab change
chrome.tabs.onActivated.addListener(function(activeInfo) {
	chrome.tabs.get(activeInfo.tabId, function(tab){

		// Handle start/stop button
    chrome.storage.sync.get(['work'], function(items) {
      if(items['work'] == 1){
        send_target(config_server, escape(tab.url), 0, 0);
      }
    });

	});
});