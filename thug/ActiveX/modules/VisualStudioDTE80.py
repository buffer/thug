
import logging
log = logging.getLogger("Thug")

def CreateObject(self, _object, param = ''):
    import thug.ActiveX as ActiveX

    log.ThugLogging.add_behavior_warn("[VisualStudio.DTE.8.0 ActiveX] CreateObject (%s)" % (_object))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "VisualStudio.DTE.8.0 ActiveX",
                                      "CreateObject",
                                      data = {
                                                "object": _object
                                             },
                                      forward = False)

    return ActiveX.ActiveX._ActiveXObject(self._window, _object)

