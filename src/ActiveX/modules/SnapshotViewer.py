# Microsoft Access Snapshot Viewer 
# CVE-2008-2463

import logging
log = logging.getLogger("Thug")

def PrintSnapshot(self, SnapshotPath = '', CompressedPath = ''):
    if SnapshotPath:
        self.SnapshotPath = SnapshotPath

    if CompressedPath:
        self.CompressedPath = CompressedPath

    msg = '[Microsoft Access Snapshot Viewer ActiveX] SnapshotPath : %s, CompressedPath: %s' % (self.SnapshotPath, 
                                                                                                self.CompressedPath, )
    log.ThugLogging.add_behavior_warn(msg, 'CVE-2008-2463')
    url = self.SnapshotPath

    try:
        response, content = self._window._navigator.fetch(url, redirect_type = "CVE-2008-2463")
    except:
        log.ThugLogging.add_behavior_warn('[Microsoft Access Snapshot Viewer ActiveX] Fetch failed')
