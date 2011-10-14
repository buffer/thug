# Microsoft MDAC RDS.Dataspace ActiveX
# CVE-2006-0003

import logging
log = logging.getLogger('Thug.ActiveX')

def CreateObject(self, object, param = ''):
    import ActiveX

    log.warning("[Microsoft MDAC RDS.Dataspace ActiveX] CreateObject (%s)" % (object))
    return ActiveX.ActiveX._ActiveXObject(object)

