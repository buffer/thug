# Microsoft XMLHTTP

import os
import httplib2
import hashlib
import logging

log = logging.getLogger("Thug")

def open(self, arg0, arg1, arg2 = True, arg3 = None, arg4 = None):
    url = str(arg1)

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.ThugLogging.add_behavior_warn('[Microsoft XMLHTTP ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] Saving File: " + filename)
  
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

    self.responseBody = content

def send(self, arg = None):
    log.ThugLogging.add_behavior_warn("[Microsoft XMLHTTP ActiveX] send")
