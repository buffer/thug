# Microsoft Access Snapshot Viewer 
# CVE-2008-2463

object = self
acct   = ActiveXAcct[self]

def PrintSnapshot(SnapshotPath = None, CompressedPath = None):
    global object
    global acct
    
    import httplib2
    import hashlib

    if SnapshotPath:
        object.SnapshotPath = SnapshotPath
    if CompressedPath:
        object.CompressedPath = CompressedPath

    acct.add_alert('[*] Microsoft Access Snapshot Viewer')
    acct.add_alert("[*] SnapshotPath     : " + object.SnapshotPath)
    acct.add_alert("[*] CompressedPath   : " + object.CompressedPath)

    url = object.SnapshotPath

    # FIXME: Relative URL
    acct.add_alert("[*] Fetching %s" % (url, ))

    headers = {
        'user-agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    }

    h = httplib2.Http('/tmp/.cache')
    response, content = h.request(str(url), headers = headers)

    md5 = hashlib.md5()
    md5.update(content)

    filename = md5.hexdigest()
		
    acct.add_alert("[*] Saving File: " + filename)
    with open(filename, 'wb') as fd:
        fd.write(content)
	
self.PrintSnapshot = PrintSnapshot
