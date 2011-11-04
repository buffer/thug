# AOL ICQ ActiveX Arbitrary File Download and Execut
# CVE-2006-5650

import hashlib
import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadAgent(self, url):
    log.warning('[AOL ICQ ActiveX] Arbitrary File Download and Execute')
    log.warning('[AOL ICQ ActiveX] Fetching from URL: %s' % (url, ))
    
    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[AOL ICQ ActiveX] Fetch failed')
        return

    if response.status == 404:
        log.warning("FileNotFoundError: %s" % (url, ))
        return 
 
    baseDir = logging.getLogger("Thug").baseDir

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()
    log.warning("[AOL ICQ ActiveX] Saving File: " + filename)    

    with open(os.path.join(baseDir, filename), 'wb') as fd: 
        fd.write(content)

