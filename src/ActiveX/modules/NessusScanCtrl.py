# Nessus Vunlnerability Scanner ScanCtrl ActiveX COntrol
# CVE-2007-4061, CVE-2007-4062, CVE-2007-4031

import logging
log = logging.getLogger("Thug.ActiveX")

def deleteReport(self, arg):
    log.warning('[Nessus ScanCtrl] deleteReport(%s)' % (arg, ))

def deleteNessusRC(self, arg):
    log.warning('[Nessus ScanCtrl] deleteNessusRC(%s)' % (arg, ))

def saveNessusRC(self, arg):
    log.warning('[Nessus ScanCtrl] saveNessusRC(%s)' % (arg, ))

def addsetConfig(self, arg, arg1, arg2):
    log.warning('[Nessus ScanCtrl] saveNessusRC(%s, %s, %s)' % (arg, arg1, arg2, ))

