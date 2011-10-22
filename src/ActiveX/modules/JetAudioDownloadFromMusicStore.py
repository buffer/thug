# jetAudio "DownloadFromMusicStore()" Arbitrary File Download Vulnerability
# CVE-2007-4983

import logging
log = logging.getLogger("Thug.ActiveX")

def DownloadFromMusicStore(self, url, dst, title, artist, album, genere, size, param1, param2):
    log.warning('JetAudio ActiveX downloading %s (saving locally as %s)' % (url, dst, ))

    try:
        response, content = self._window._navigator.fetch(url)
    except:
        log.warning('[JetAudio ActiveX] Fetch failed')

