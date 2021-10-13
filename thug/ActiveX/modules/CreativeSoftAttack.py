
import logging

log = logging.getLogger("Thug")


def Setcachefolder(self, val): # pylint:disable=unused-argument
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "CreativeSoft ActiveX",
                                      "Overflow in cachefolder property")
