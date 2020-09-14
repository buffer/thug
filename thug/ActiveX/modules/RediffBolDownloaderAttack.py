
import logging

log = logging.getLogger("Thug")


def Seturl(self, val):
    self.__dict__['url'] = val

    log.ThugLogging.log_exploit_event(self._window.url,
                                      "RediffBolDownloader ActiveX",
                                      "Overflow in url property")
    log.ThugLogging.Shellcode.check_shellcode(val)
