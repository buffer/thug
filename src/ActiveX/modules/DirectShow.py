# Microsoft DirectShow MPEG2TuneRequest Component Stack Overflow(MS09-032)
# CVE-2008-0015,CVE-2008-0020

import logging
log = logging.getLogger("Thug")

def Setdata(self, val):
    self.__dict__['data'] = val
    log.ThugLogging.add_behavior_warn('[Microsoft DirectShow MPEG2TuneRequest ActiveX] Stack Overflow in data property',
                               'CVE-2008-0015')

