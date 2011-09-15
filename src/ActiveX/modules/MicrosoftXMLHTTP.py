# Microsoft XMLHTTP

object = self
acct   = ActiveXAcct[self]

def open(arg0, arg1, arg2 = True, arg3 = None, arg4 = None):
    global object
    global acct

    import httplib2
    import hashlib

    url = str(arg1)
	
    acct.add_alert('[*] Microsoft XMLHTTP')
    acct.add_alert("[*] Method : " + arg0)
    acct.add_alert("[*] URL    : " + url)
    acct.add_alert("[*] Fetching %s" % (url, ))

    headers = {
        'user-agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    }

    h = httplib2.Http('/tmp/.cache')

    #FIXME: Relative URLs
    response, content = h.request(str(url), headers = headers)

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    acct.add_alert("[*] Saving File: " + filename)
    
    with open(filename, 'wb') as fd:
        fd.write(content)
		
    object.responseBody = content
	
self.open = open
