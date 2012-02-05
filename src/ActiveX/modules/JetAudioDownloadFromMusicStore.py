# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

import hashlib
import logging
log = logging.getLogger("Thug")

def DownloadFromMusicStore(self, url, dst, title, artist, album, genere, size, param1, param2):
    log.MAEC.add_behavior_warn('[JetAudio ActiveX] Downloading from URL %s (saving locally as %s)' % (url, dst, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.MAEC.add_behavior_warn('[JetAudio ActiveX] Fetch failed')
        return
    
    if response.status == 404:
        log.MAEC.add_behavior_warn("[JetAudio ActiveX] FileNotFoundError: %s" % (url, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.MAEC.add_behavior_warn("[JetAudio ActiveX] Saving File: " + filename)
  
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass
