# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

import logging
log = logging.getLogger("Thug")

def CreateObject(self, object, param = ''):
    import ActiveX

    log.MAEC.add_behavior_warn("[Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (%s)" % (object))
    return ActiveX.ActiveX._ActiveXObject(self._window, object)

