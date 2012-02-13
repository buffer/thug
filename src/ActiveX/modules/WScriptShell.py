
import logging
log = logging.getLogger("Thug")

class _Environment:
    def __init__(self, strType):
        self.strType = strType

    def Item(self, item):
        log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Getting Environment Item: %s" % (item, ))
        return item

def Run(self, strCommand, intWindowStyle = 1, bWaitOnReturn = False):
    log.ThugLogging.add_behavior_warn("[WScript.Shell ActiveX] Executing: %s" % (strCommand, ))

def Environment(self, strType = None):
    log.ThugLogging.add_behavior_warn('[WScript.Shell ActiveX] Environment("%s")' % (strType, ))
    return _Environment(strType)
