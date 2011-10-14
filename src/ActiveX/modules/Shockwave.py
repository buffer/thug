
import logging
log = logging.getLogger("Thug.ActiveX")

def ShockwaveVersion(self, arg):
    if len(arg) >= 768 * 768:
        log.warning('Adobe Shockwave ShockwaveVersion Stack Overflow')

