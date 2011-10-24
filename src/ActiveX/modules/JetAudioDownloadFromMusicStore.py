# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

import hashlib
import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadFromMusicStore(self, url, dst, title, artist, album, genere, size, param1, param2):
    log.warning('[JetAudio ActiveX] Downloading from URL %s (saving locally as %s)' % (url, dst, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[JetAudio ActiveX] Fetch failed')
        return
    
    if response.status == 404:
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.warning("[JetAudio ActiveX] Saving File: " + filename)
  
    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass
