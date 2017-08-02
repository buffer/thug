# RTS Sentry Digital Surveillance PTZCamPanel Class (CamPanel.dll 2.1.0.2)
# CVE-NOMATCH

import logging

log = logging.getLogger("Thug")


def ConnectServer(self, server, user):
    if len(user) > 1024:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "PTZCamPanel ActiveX",
                                          "Overflow in ConnectServer user arg")
        log.DFT.check_shellcode(user)
