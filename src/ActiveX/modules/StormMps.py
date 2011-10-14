# MPS.StormPlayer.1  'advanceOpen' 
# CVE

import logging
log = logging.getLogger("Thug.ActiveX")

def advancedOpen(self, arg0, arg1):
    if len(arg0) > 259:
        log.warning('MPS.StormPlayer.1 ActiveX advanceOpen Method Overflow')

def isDVDPath(self, arg0):
    if len(arg0) > 246:
        log.warning('MPS.StormPlayer.1 ActiveX isDVDPath Method Overflow')

def rawParse(self, arg0):
    if len(arg0) > 259:
        log.warning('MPS.StormPlayer.1 ActiveX rawParse Method Overflow')

def OnBeforeVideoDownload(self, arg0):
    if len(arg0) > 4124:
        log.warning('MPS.StromPlayer.1 ActiveX OnBeforeVideoDownload Method Overflow')

def SetURL(self, val):
    self.__dict__['URL'] = val

    if len(val) > 259:
        log.warning('MPS.StormPlayer.1 ActiveX URL Console Overflow')

def SetbackImage(self, val):
    self.__dict__['backImage'] = val

    if len(val) > 292:
        log.warning('MPS.StormPlayer.1 ActiveX backImage Console Overflow')

def SettitleImage(self, val):
    self.__dict__['titleImage'] = val

    if len(val) > 296:
        log.warning('MPS.StromPlayer.1 ActiveX titleImage Console Overflow')



