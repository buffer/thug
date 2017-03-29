# Microsoft DirectShow MPEG2TuneRequest Component Stack Overflow(MS09-032)
# CVE-2008-0015,CVE-2008-0020

import logging

log = logging.getLogger("Thug")


def Setdata(self, val):
    self.__dict__['data'] = val
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Microsoft DirectShow MPEG2TuneRequest ActiveX",
                                      "Stack Overflow in data property",
                                      cve = 'CVE-2008-0015')

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2008-0015", None)
