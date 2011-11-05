
import os
import hashlib
import httplib2

import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadFile(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in DownloadFile function')

    log.warning('[ZenturiProgramChecker ActiveX] Downloading from %s' % (arg[0], ))
    log.warning("[ZenturiProgramChecker ActiveX] Saving downloaded file as: %s" % (arg[1], ))

    try:
        response, content = self._window._navigator.fetch(arg[0])
    except:
        log.warning('[ZenturiProgramChecker ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.warning("FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.warning("[ZenturiProgramChecker ActiveX] Saving File: %s" % (filename, ))

    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def DebugMsgLog(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in DebugMsgLog function')

def NavigateUrl(self, *arg):
    log.warning('ZenturiProgramChecker ActiveX Attack in NavigateUrl function')

