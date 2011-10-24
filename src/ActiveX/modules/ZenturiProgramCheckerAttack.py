
import os
import hashlib
import httplib2

import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadFile(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in DownloadFile function')

    #h = httplib2.Http('/tmp/.cache')

    #headers = {
    #    'user-agent' : logging.getLogger("Thug").userAgent,
    #}

    #FIXME: Relative URLs
    try:
        #response, content = h.request(arg[0], headers = headers)
        response, content = self._window._navigator.fecth(arg[0])
    except:
        log.warning('[ZenturiProgramChecker ActiveX] Fetch failed')

    if response.status == 404:
        log.warning("FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.warning("[ZenturiProgramChecker ActiveX] Saving File: %s" % (filename, ))
    
    with open(os.path.join(object._log.baseDir, filename), 'wb') as fd:
        fd.write(content)

def DebugMsgLog(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in DebugMsgLog function')

def NavigateUrl(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in NavigateUrl function')

