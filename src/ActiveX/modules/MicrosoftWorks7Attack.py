
import logging
log = logging.getLogger("Thug.ActiveX")

def SetWksPictureInterface(self, val):
    self.__dict__['WksPictureInterface'] = val

    log.warning('MicrosoftWorks7 ActiveX overflow in WksPictureInterface property')

