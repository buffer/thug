
import logging
log = logging.getLogger("Thug.ActiveX")

def Seturl(self, val):
    self.__dict__['url'] = val

    log.warning('RediffBolDownloader ActiveX Overflow in url property')

