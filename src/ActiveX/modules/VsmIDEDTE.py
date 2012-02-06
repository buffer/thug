
import logging
log = logging.getLogger("Thug")

def CreateObject(self, object, param = ''):
    import ActiveX

    log.MAEC.add_behavior_warn("[VsmIDE.DTE ActiveX] CreateObject (%s)" % (object))
    return ActiveX.ActiveX._ActiveXObject(self._window, object)

