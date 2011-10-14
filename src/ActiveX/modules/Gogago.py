# Gogago YouTube Video Converter Buffer Overflow
# HTB23012

import logging 
log = logging.getLogger("Thug.ActiveX")

def Download(self, arg):
    if len(arg) > 1024:
        log.warning('Gogago YouTube Video Converter Buffer Overflow')
