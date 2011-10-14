# Microsoft DirectShow MPEG2TuneRequest Component Stack Overflow(MS09-032)
# CVE-2008-0015,CVE-2008-0020

import logging
log = logging.getLogger("Thug.ActiveX")

def Setdata(self, val):
    self.__dict__['data'] = val
    log.warning('Microsoft DirectShow MPEG2TuneRequest Component Stack Overflow in data property')

