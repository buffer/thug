# Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX) Arbitrary file download/overwrite Exploit

import logging

log = logging.getLogger("Thug")


def GetToFile(self, url, _file):
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX)",
                                      "Arbitrary File Download/Overwrite Exploit",
                                      data = {
                                                "url" : url,
                                                "file": _file
                                             }
                                     )
