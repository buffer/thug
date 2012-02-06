# RealMedia RealPlayer Ierpplug.DLL ActiveX Control
# CVE-2007-5601

import logging
log = logging.getLogger("Thug")

def DoAutoUpdateRequest(self, arg0, arg1, arg2):
    if len(arg0) > 1000 or len(arg1) > 1000:
        log.MAEC.add_behavior_warn('[RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in DoAutoUpdateRequest',
                                   'CVE-2007-5601')

def PlayerProperty(self, arg):
    if arg == 'PRODUCTVERSION':
        return '6.0.14.552'

    if len(arg) > 1000:
        log.MAEC.add_behavior_warn('[RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in PlayerProperty',
                                   'CVE-2007-5601')

def Import(self, arg):
    if len(arg) > 0x8000:
        log.MAEC.add_behavior_warn('[RealMedia RealPlayer Ierpplug.DLL ActiveX] Overflow in Import',
                                   'CVE-2007-5601')

def SetConsole(self, val):
    self.__dict__['Console'] = val

    if len(val) >= 32:
        log.MAEC.add_behavior_warn('[RealMedia RealPlayer rmoc3260.DLL ActiveX] Overflow in Console property',
                                   'CVE-2007-5601')

