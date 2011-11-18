# Microsoft Access Snapshot Viewer 
# CVE-2008-2463

import os
import httplib2
import hashlib
import logging

log = logging.getLogger("Thug.ActiveX")


def PrintSnapshot(self, SnapshotPath = '', CompressedPath = ''):
    if SnapshotPath:
        self.SnapshotPath = SnapshotPath

    if CompressedPath:
        self.CompressedPath = CompressedPath

    log.warning('[Microsoft Access Snapshot Viewer ActiveX] SnapshotPath : %s, CompressedPath: %s' % (self.SnapshotPath, self.CompressedPath, ))

    url = self.SnapshotPath

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[Microsoft Access Snapshot Viewer ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.warning("FileNotFoundError: %s" % (url, ))
        return 
 
    baseDir = logging.getLogger("Thug").baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
		
    log.warning("[Microsoft Access Snapshot Viewer ActiveX] Saving File: " + filename)
    with open(os.path.join(baseDir, filename), 'wb') as fd:
        fd.write(content)
	
