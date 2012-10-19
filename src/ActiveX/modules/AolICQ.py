# AOL ICQ ActiveX Arbitrary File Download and Execut
# CVE-2006-5650

import logging
log = logging.getLogger("Thug")

def DownloadAgent(self, url):
    log.ThugLogging.add_behavior_warn('[AOL ICQ ActiveX] Arbitrary File Download and Execute', 'CVE-2006-5650')
    log.ThugLogging.add_behavior_warn('[AOL ICQ ActiveX] Fetching from URL: %s' % (url, ))
    
    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.ThugLogging.add_behavior_warn('[AOL ICQ ActiveX] Fetch failed')
