# Multiple Office OCX ActiveX Controls 'OpenWebFile()' Arbitrary 
# Program Execution Vulnerability
# BID-33243

import os
import hashlib
import logging
log = logging.getLogger("Thug")


def OpenWebFile(self, _file):
    log.ThugLogging.add_behavior_warn('[Office OCX ActiveX] OpenWebFile Arbitrary Program Execution Vulnerability')
    log.ThugLogging.add_behavior_warn("[Office OCX ActiveX] Fetching from URL %s" % (_file, ))

    try:
        response, content = self._window._navigator.fetch(_file)
    except:
        log.ThugLogging.add_behavior_warn('[Office OCX ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.ThugLogging.add_behavior_warn("[Office OCX ActiveX] FileNotFoundError: %s" % (_file, ))
        return 
 
    baseDir = log.baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.ThugLogging.add_behavior_warn("[Office OCX ActiveX] Saving File: " + filename)    

    with open(os.path.join(baseDir, filename), 'wb') as fd: 
        fd.write(content)
