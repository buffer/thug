
import logging
log = logging.getLogger("Thug")

def Seturl(self, val):
    self.__dict__['url'] = val

    log.ThugLogging.add_behavior_warn('[RediffBolDownloader ActiveX] Overflow in url property')

