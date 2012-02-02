# BitDefender Online Scanner ActiveX Control
# CVE-2007-5775

import logging
log = logging.getLogger("Thug")

def initx(self, arg):
    if len(arg) > 1024:
        log.MAEC.add_behavior_warn('BitDefender Online Scanner InitX overflow')

