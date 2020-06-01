# Nessus Vunlnerability Scanner ScanCtrl ActiveX Control
# CVE-2007-4061, CVE-2007-4062, CVE-2007-4031

import logging

log = logging.getLogger("Thug")


def deleteReport(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] deleteReport(%s)' % (arg, ),
                                      'CVE-2007-4031')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Nessus Vunlnerability Scanner ScanCtrl ActiveX",
                                      "deleteReport",
                                      cve = "CVE-2007-4031",
                                      data = {
                                                "arg": arg
                                             },
                                      forward = False)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-4031")


def deleteNessusRC(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] deleteNessusRC(%s)' % (arg, ),
                                      'CVE-2007-4062')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Nessus Vunlnerability Scanner ScanCtrl ActiveX",
                                      "deleteNEssusRC",
                                      cve = "CVE-2007-4062",
                                      data = {
                                                "arg": arg
                                             },
                                      forward = False)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-4062")


def saveNessusRC(self, arg):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] saveNessusRC(%s)' % (arg, ),
                                      'CVE-2007-4061')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Nessus Vunlnerability Scanner ScanCtrl ActiveX",
                                      "saveNessusRC",
                                      cve = "CVE-2007-4061",
                                      data = {
                                                "arg": arg
                                             },
                                      forward = False)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-4061")


def addsetConfig(self, arg, arg1, arg2):
    log.ThugLogging.add_behavior_warn('[Nessus Vunlnerability Scanner ScanCtrl ActiveX] addsetConfig(%s, %s, %s)' % (arg, arg1, arg2, ),
                                      'CVE-2007-4061')
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Nessus Vunlnerability Scanner ScanCtrl ActiveX",
                                      "addsetConfig",
                                      cve = "CVE-2007-4061",
                                      data = {
                                                "arg" : arg,
                                                "arg1": arg1,
                                                "arg2": arg2
                                             },
                                      forward = False)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-4061")
