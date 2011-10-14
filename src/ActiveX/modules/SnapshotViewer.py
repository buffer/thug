# Microsoft Access Snapshot Viewer 
# CVE-2008-2463

import httplib2
import hashlib

import logging
log = logging.getLogger("Thug.ActiveX")

def PrintSnapshot(self, SnapshotPath = '', CompressedPath = ''):
    self.SnapshotPath = SnapshotPath
    self.CompressedPath = CompressedPath

    log.warning('[*] Microsoft Access Snapshot Viewer [SnapshotPath : %s, CompressedPath: %s]' % SnapshotPath, CompressedPath)

    url = self.SnapshotPath

    # FIXME: Relative URL
    log.warning("[*] Fetching %s" % (url, ))

    headers = {
        'user-agent' : 'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP; .NET CLR 1.1.4322; .NET CLR 2.0.50727)'
    }

    h = httplib2.Http('/tmp/.cache')
    response, content = h.request(str(url), headers = headers)

    md5 = hashlib.md5()
    md5.update(content)

    filename = md5.hexdigest()
		
    log.warning("[*] Saving File: " + filename)
    with open(filename, 'wb') as fd:
        fd.write(content)
	
