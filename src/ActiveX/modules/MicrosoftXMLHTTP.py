# Microsoft XMLHTTP

import os
import httplib2
import hashlib
import logging

log = logging.getLogger("Thug.ActiveX")

def open(self, arg0, arg1, arg2 = True, arg3 = None, arg4 = None):
    url = str(arg1)
	
    log.warning("[Microsoft XMLHTTP ActiveX] Fetching from URL %s" % (url, ))

    #headers = {
    #    'user-agent' : logging.getLogger("Thug").userAgent,
    #}

    #h = httplib2.Http('/tmp/.cache')

    #FIXME: Relative URLs
    try:
        #response, content = h.request(url, headers = headers)
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[Microsoft XMLHTTP ActiveX] Fetch failed')
        return

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.warning("[Microsoft XMLHTTP ActiveX] Saving File: " + filename)
  
    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

    self.responseBody = content

def send(self, arg = None):
    pass
