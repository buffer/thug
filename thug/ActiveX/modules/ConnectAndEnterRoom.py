# GlobalLink ConnectAndEnterRoom ActiveX Control ConnectAndEnterRoom() Method Overflow Vulnerability
# CVE-2007-5722

import logging

log = logging.getLogger("Thug")


def ConnectAndEnterRoom(self, arg0, arg1, arg2, arg3, arg4, arg5):
    if len(arg0) > 172:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "GlobalLink ConnectAndEnterRoom ActiveX",
                                          "ConnectAndEnterRoom Overflow",
                                          cve = 'CVE-2007-5722')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-5722")
        log.ThugLogging.Shellcode.check_shellcode(arg0)
