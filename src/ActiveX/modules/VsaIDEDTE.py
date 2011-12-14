
import logging
log = logging.getLogger('Thug.ActiveX')

def CreateObject(self, object, param = ''):
    import ActiveX

    log.warning("[VsaIDE.DTE ActiveX] CreateObject (%s)" % (object))
    return ActiveX.ActiveX._ActiveXObject(self._window, object)

