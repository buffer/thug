# Symantec AppStream LaunchObj ActiveX Arbitrary File Download and Execute
# CVE-2008-4388

import os
import hashlib
import logging

log = logging.getLogger("Thug")

def installAppMgr(self, url):
    log.ThugLogging.add_behavior_warn('[Symantec AppStream LaunchObj ActiveX] Arbitrary File Download and Execute',
                                      'CVE-2008-4388')

    log.ThugLogging.add_behavior_warn("[Symantec AppStream LaunchObj ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.ThugLogging.add_behavior_warn('[Symantec AppStream LaunchObj ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.ThugLogging.add_behavior_warn("[Symantec AppStream LaunchObj ActiveX] FileNotFoundError: %s" % (url, ))
        return 
 
    baseDir = log.baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.ThugLogging.add_behavior_warn("[Symantec AppStream LaunchObj ActiveX] Saving File: " + filename)    

    with open(os.path.join(baseDir, filename), 'wb') as fd: 
        fd.write(content)

