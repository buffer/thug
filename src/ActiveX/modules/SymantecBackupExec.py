# Symantec BackupExec
# CVE-2007-6016,CVE-2007-6017

import logging
log = logging.getLogger("Thug.ActiveX")

def Set_DOWText0(self, val):
    self.__dict__['_DOWText0'] = val

    if len(val) > 255:
        log.warning('SymantecBackupExec overflow in property _DOWText0')

def Set_DOWText6(self, val):
    self.__dict__['_DOWText6'] = val

    if len(val) > 255:
        log.warning('SymantecBackupExec overflow in property _DOWText6')

def Set_MonthText0(self, val):
    self.__dict__['_MonthText0'] = val

    if len(val) > 255:
        log.warning('SymantecBackupExec overflow in property _MonthText0')

def Set_MonthText11(self, val):
    self.__dict__['_MonthText11'] = val

    if len(val) > 255:
        log.warning('SymantecBackupExec overflow in property _MonthText11')

def Save(self, a, b):
    return
