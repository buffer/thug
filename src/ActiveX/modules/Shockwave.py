
import logging
log = logging.getLogger("Thug")

def ShockwaveVersion(self, arg):
    if len(arg) >= 768 * 768:
        log.ThugLogging.add_behavior_warn('[Adobe Shockwave ActiveX] ShockwaveVersion Stack Overflow')

