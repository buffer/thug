# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

import logging

log = logging.getLogger("Thug")


def CreateObject(self, _object, param = ''):
    import thug.ActiveX as ActiveX

    log.ThugLogging.add_behavior_warn("[Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (%s)" % (_object))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft MDAC RDS.Dataspace ActiveX",
                                      "CreateObject",
                                      forward = False,
                                      data = {
                                                "object": _object
                                             }
                                     )

    return ActiveX.ActiveX._ActiveXObject(self._window, _object)
