# Move Networks Quantum Streaming Player Control
# CVE-NOMATCH

import logging
log = logging.getLogger("Thug.ActiveX")

def UploadLogs(self, url, arg):
    if len(url) > 20000:
        log.warning('Quantum Streaming Player overflow in UploadLogs method')
