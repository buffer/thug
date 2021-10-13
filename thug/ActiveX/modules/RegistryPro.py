# Registry Pro (epRegPro.ocx)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def DeleteKey(self, arg0, arg1):
    if arg0 in (80000001, 80000002, ):
        log.ThugLogging.add_behavior_warn(f'[RegistryPro ActiveX] Deleting [HKEY_LOCAL_MACHINE/{arg1}]')
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "RegistryPro ActiveX",
                                          "Deleting Regkey",
                                          forward = False,
                                          data = {
                                              "regkey": "HKEY_LOCAL_MACHINE/" + str(arg1)
                                          })


def About(self): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn('[RegistryPro ActiveX] About called')
