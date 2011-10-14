# Microsoft VFP_OLE_Server

import logging
log = logging.getLogger("Thug.ActiveX")

def foxcommand(self, cmd):
    log.warning('Microsoft VFP_OLE_Server is attempting to run: %s' % (cmd, ))

