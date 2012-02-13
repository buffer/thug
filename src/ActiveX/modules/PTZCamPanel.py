# RTS Sentry Digital Surveillance PTZCamPanel Class (CamPanel.dll 2.1.0.2)
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug")

def ConnectServer(self, server, user):
    if len(user) > 1024:
        log.ThugLogging.add_behavior_warn('[PTZCamPanel ActiveX] Overflow in ConnectServer user arg')

