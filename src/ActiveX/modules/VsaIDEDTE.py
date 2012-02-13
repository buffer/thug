
import logging
log = logging.getLogger("Thug")

def CreateObject(self, object, param = ''):
    import ActiveX

    log.ThugLogging.add_behavior_warn("[VsaIDE.DTE ActiveX] CreateObject (%s)" % (object))
    return ActiveX.ActiveX._ActiveXObject(self._window, object)

