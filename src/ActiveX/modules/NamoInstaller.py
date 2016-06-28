# NamoInstaller ActiveX Control 1.x - 3.x
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def Install(self, arg):
    if len(arg) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "NamoInstaller ActiveX",
                                          "Overflow in Install method")

    if str([arg]).find('http') > -1:
        log.ThugLogging.add_behavior_warn('[NamoInstaller ActiveX] Insecure download from URL %s' % (arg, ))
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "NamoInstaller ActiveX",
                                          "Insecure download from URL",
                                          forward = False,
                                          data = {
                                                    "url": arg
                                                 }
                                         )
        try:
            self._window._navigator.fetch(arg, redirect_type = "NamoInstaller Exploit")
        except: #pylint:disable=bare-except
            log.ThugLogging.add_behavior_warn('[NamoInstaller ActiveX] Fetch failed')
