# Sina DLoader Class ActiveX Control 'DonwloadAndInstall' 
# Method Arbitrary File Download Vulnerability

import os
import hashlib
import logging
log = logging.getLogger("Thug")

def DownloadAndInstall(self, url):
    log.ThugLogging.add_behavior_warn("[SinaDLoader Downloader ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.ThugLogging.add_behavior_warn('[SinaDLoader Downloader ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.ThugLogging.add_behavior_warn("[SinaDLoader Downloader ActiveX] FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.ThugLogging.add_behavior_warn("[SinaDLoader Downloader ActiveX] Saving File: " + filename)
  
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

