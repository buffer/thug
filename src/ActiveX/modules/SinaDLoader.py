# Sina DLoader Class ActiveX Control 'DonwloadAndInstall' 
# Method Arbitrary File Download Vulnerability

import os
import hashlib
import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadAndInstall(self, url):
    log.warning("[SinaDLoader Downloader ActiveX] Fetching from URL %s" % (url, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[SinaDLoader Downloader ActiveX] Fetch failed')
        return

    if response.status == 404:
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.warning("[SinaDLoader Downloader ActiveX] Saving File: " + filename)
  
    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

