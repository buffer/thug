# SSReader Pdg2 ActiveX control (pdg2.dll)
# CVE-2007-5892

import logging
log = logging.getLogger("Thug.ActiveX")

def Register(self, arg0, arg1):
    if len(arg1) > 255:
        log.warning('SSReader Pdg2 ActiveX Register Method Overflow')

def LoadPage(self, arg0, arg1, arg2, arg3):
    if len(arg0) > 255:
        log.warning('SSReader Pdg2 ActiveX LoadPage Method Overflow')

