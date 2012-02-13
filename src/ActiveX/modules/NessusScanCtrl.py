# Nessus Vunlnerability Scanner ScanCtrl ActiveX Control
# CVE-2007-4061, CVE-2007-4062, CVE-2007-4031

import logging
log = logging.getLogger("Thug")

def deleteReport(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] deleteReport(%s)' % (arg, ),
                               'CVE-2007-4031')

def deleteNessusRC(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] deleteNessusRC(%s)' % (arg, ),
                               'CVE-2007-4062')

def saveNessusRC(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] saveNessusRC(%s)' % (arg, ),
                               'CVE-2007-4061')

def addsetConfig(self, arg, arg1, arg2):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] saveNessusRC(%s, %s, %s)' % (arg, arg1, arg2, ),
                               'CVE-2007-4061')

