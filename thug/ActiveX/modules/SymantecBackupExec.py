# Symantec BackupExec
# CVE-2007-6016,CVE-2007-6017

import logging

log = logging.getLogger("Thug")


def Set_DOWText0(self, val):
    self.__dict__['_DOWText0'] = val

    if len(val) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Symantec BackupExec ActiveX",
                                          "Overflow in property _DOWText0",
                                          cve = 'CVE-2007-6016')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6016", None)
        log.DFT.check_shellcode(val)


def Set_DOWText6(self, val):
    self.__dict__['_DOWText6'] = val

    if len(val) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Symantec BackupExec ActiveX",
                                          "Overflow in property _DOWText6",
                                          cve = 'CVE-2007-6016')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6016", None)
        log.DFT.check_shellcode(val)


def Set_MonthText0(self, val):
    self.__dict__['_MonthText0'] = val

    if len(val) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Symantec BackupExec ActiveX",
                                          "Overflow in property _MonthText6",
                                          cve = 'CVE-2007-6016')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6016", None)
        log.DFT.check_shellcode(val)


def Set_MonthText11(self, val):
    self.__dict__['_MonthText11'] = val

    if len(val) > 255:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Symantec BackupExec ActiveX",
                                          "Overflow in property _MonthText11",
                                          cve = 'CVE-2007-6016')

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6016", None)
        log.DFT.check_shellcode(val)


def Save(self, a, b):
    return
