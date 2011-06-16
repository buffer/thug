# Microsoft XMLHTTP

object = self
#FIXME
hc = self.__dict__['__options']['hc']

def open(arg0, arg1, arg2 = True, arg3 = None, arg4 = None):
	global hc, object
	_url = str(arg1)
	add_alert('[*] Microsoft XMLHTTP')
	add_alert("[*] Method : " + arg0)
	add_alert("[*] URL    : " + _url)

	urls = set()
	if _url.startswith("/"):
		for base in os.environ['PHONEYC_URLBASE'].split(";"):
			urls.add(base + _url)       
	else:
		urls.add(_url)

	import hashlib

	for url in urls:
		h = hashlib.md5()
		add_alert("[*] Fetching %s" % (url, ))
		content, headers = hc.get(str(url))
		h.update(content)
		filename = "log/downloads/binaries/%s" % (h.hexdigest(), )
		add_alert("[*] Saving File: " + filename)
		fd = open(filename, 'wb')
		fd.write(content)
		fd.close()
		object.responseBody = content
	
self.open = open
