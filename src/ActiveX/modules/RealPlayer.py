# RealMedia RealPlayer Ierpplug.DLL ActiveX Control
# CVE-2007-5601

import logging
log = logging.getLogger("Thug.ActiveX")

def DoAutoUpdateRequest(self, arg0, arg1, arg2):
    if len(arg0) > 1000 or len(arg1) > 1000:
        log.warning('RealPlayer 10.5 ierpplug.dll overflow in DoAutoUpdateRequest')

def PlayerProperty(self, arg):
    if arg == 'PRODUCTVERSION':
        return '6.0.14.552'

    if len(arg) > 1000:
        log.warning('RealPlayer 10.5 ierpplug.dll overflow in PlayerProperty')

def Import(self, arg):
    if len(arg) > 0x8000:
        log.warning('RealPlayer 10.5 ierpplug.dll overflow in Import')

def SetConsole(self, val):
    self.__dict__['Console'] = val

    if len(val) >= 32:
        log.warning('RealPlayer rmoc3260.dll overflow in Console property')

