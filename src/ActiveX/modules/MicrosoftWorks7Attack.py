
import logging
log = logging.getLogger("Thug")

def SetWksPictureInterface(self, val):
    self.__dict__['WksPictureInterface'] = val

    log.ThugLogging.log_exploit_event(self._window.url,
                                      "MicrosoftWorks7 ActiveX",
                                      "Overflow in WksPictureInterface property")
