# NCTsoft Products NCTAudioFile2 ActiveX Control
# CVE-2007-0018

import logging

log = logging.getLogger("Thug")


def SetFormatLikeSample(self, arg):
    if len(arg) > 4000:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "NCTAudioFile2 ActiveX",
                                          "Overflow in SetFormatLikeSample",
                                          cve = "CVE-2007-0018")
