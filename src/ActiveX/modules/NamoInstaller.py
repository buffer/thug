# NamoInstaller ActiveX Control 1.x - 3.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def Install(self, arg):
    if len(arg) > 1024:
        log.warning('[NamoInstaller ActiveX] Overflow in Install method')

    if str([arg]).find('http') > -1:
        log.warning('[NamoInstaller ActiveX] Insecure download from URL %s' % (arg, ))
        try:
            response, content = self._window._navigator.fetch(url)
        except:
            log.warning('[NamoInstaller ActiveX] Fetch failed')
            return

        if response.status == 404:
            log.warning("FileNotFoundError: %s" % (url, ))
