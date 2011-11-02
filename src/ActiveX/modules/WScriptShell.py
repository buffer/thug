
import logging
log = logging.getLogger("Thug.ActiveX")

class _Environment:
    def __init__(self, strType):
        self.strType = strType

    def Item(self, item):
        log.warning("[WScript.Shell ActiveX] Getting Environment Item: %s" % (item, ))
        return item

def Run(self, strCommand, intWindowStyle = 1, bWaitOnReturn = False):
    log.warning("[WScript.Shell ActiveX] Executing: %s" % (strCommand, ))

def Environment(self, strType = None):
    log.warning('[WScript.Shell ActiveX] Environment("%s")' % (strType, ))
    return _Environment(strType)
