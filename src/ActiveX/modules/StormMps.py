# MPS.StormPlayer.1  'advanceOpen' 
# CVE

import logging
log = logging.getLogger("Thug")

def advancedOpen(self, arg0, arg1):
    if len(arg0) > 259:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "advanceOpen Method Overflow")

def isDVDPath(self, arg0):
    if len(arg0) > 246:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "isDVDPath Method Overflow")

def rawParse(self, arg0):
    if len(arg0) > 259:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "rawParse Method Overflow")

def OnBeforeVideoDownload(self, arg0):
    if len(arg0) > 4124:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "OnBeforeVideoDownload Method Overflow")

def SetURL(self, val):
    self.__dict__['URL'] = val

    if len(val) > 259:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "URL Console Overflow")

def SetbackImage(self, val):
    self.__dict__['backImage'] = val

    if len(val) > 292:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "backImage Console Overflow")

def SettitleImage(self, val):
    self.__dict__['titleImage'] = val

    if len(val) > 296:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "MPS.StormPlayer.1 ActiveX",
                                          "titleImage Console Overflow")
