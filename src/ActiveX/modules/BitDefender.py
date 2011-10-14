# BitDefender Online Scanner ActiveX Control
# CVE-2007-5775

import logging
log = logging.getLogger("Thug.ActiveX")

def initx(self, arg):

    if len(arg) > 1024:
        log.warning('BitDefender Online Scanner InitX() overflow')

