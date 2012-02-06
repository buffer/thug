
import os
import hashlib
import httplib2

import logging
log = logging.getLogger("Thug")

def DownloadFile(self, *arg):
    log.MAEC.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DownloadFile function')

    log.MAEC.add_behavior_warn('[ZenturiProgramChecker ActiveX] Downloading from %s' % (arg[0], ))
    log.MAEC.add_behavior_warn("[ZenturiProgramChecker ActiveX] Saving downloaded file as: %s" % (arg[1], ))

    try:
        response, content = self._window._navigator.fetch(arg[0])
    except:
        log.MAEC.add_behavior_warn('[ZenturiProgramChecker ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.MAEC.add_behavior_warn("[ZenturiProgramChecker ActiveX] FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.MAEC.add_behavior_warn("[ZenturiProgramChecker ActiveX] Saving File: %s" % (filename, ))

    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def DebugMsgLog(self, *arg):
    log.MAEC.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in DebugMsgLog function')

def NavigateUrl(self, *arg):
    log.MAEC.add_behavior_warn('[ZenturiProgramChecker ActiveX] Attack in NavigateUrl function')

