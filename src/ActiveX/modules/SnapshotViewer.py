# Microsoft Access Snapshot Viewer 
# CVE-2008-2463

object = self
hc = self.__dict__['__options']['hc']

def PrintSnapshot(SnapshotPath = None, CompressedPath = None):
	global hc, object
	import hashlib

	if SnapshotPath:
		object.SnapshotPath = SnapshotPath
	if CompressedPath:
		object.CompressedPath = CompressedPath

	add_alert('[*] Microsoft Access Snapshot Viewer')
	add_alert("[*] SnapshotPath     : " + object.SnapshotPath)
	add_alert("[*] CompressedPath   : " + object.CompressedPath)

	url = object.SnapshotPath
	urls = set()
	if url.startswith("/"):
		for base in os.environ['PHONEYC_URLBASE'].split(";"):
			urls.add(base + url)       
	else:
		urls.add(url)

	for url in urls:
		print "[*] Fetching %s" % (url, )
		h = hashlib.md5()
		content, headers = hc.get(str(url))
		h.update(content)
		filename = "log/downloads/binaries/%s" % (h.hexdigest(), )
		add_alert("[*] Saving File: " + filename)
		fd = open(filename, 'wb')
		fd.write(content)
		fd.close()
	
self.PrintSnapshot = PrintSnapshot
