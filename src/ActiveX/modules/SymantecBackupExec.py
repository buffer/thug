# Symantec BackupExec
# CVE-2007-6016,CVE-2007-6017

import logging
log = logging.getLogger("Thug")

def Set_DOWText0(self, val):
    self.__dict__['_DOWText0'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[Symantec BackupExec ActiveX] Overflow in property _DOWText0',
                                   'CVE-2007-6016')

def Set_DOWText6(self, val):
    self.__dict__['_DOWText6'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[Symantec BackupExec ActiveX] Overflow in property _DOWText6',
                                   'CVE-2007-6016')

def Set_MonthText0(self, val):
    self.__dict__['_MonthText0'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[Symantec BackupExec ActiveX] Overflow in property _MonthText0',
                                   'CVE-2007-6016')

def Set_MonthText11(self, val):
    self.__dict__['_MonthText11'] = val

    if len(val) > 255:
        log.ThugLogging.add_behavior_warn('[Symantec BackupExec ActiveX] Overflow in property _MonthText11',
                                   'CVE-2007-6016')

def Save(self, a, b):
    return
