# NCTsoft Products NCTAudioFile2 ActiveX Control
# CVE-2007-0018

import logging
log = logging.getLogger("Thug.ActiveX")

def SetFormatLikeSample(self, arg):
    if len(arg) > 4000:
        log.warning('NCTAudioFile2 overflow in SetFormatLikeSample')

