# NCTsoft Products NCTAudioFile2 ActiveX Control
# CVE-2007-0018

import logging
log = logging.getLogger("Thug")

def SetFormatLikeSample(self, arg):
    if len(arg) > 4000:
        log.MAEC.add_behavior_warn('[NCTAudioFile2 ActiveX] Overflow in SetFormatLikeSample',
                                   'CVE-2007-0018')

