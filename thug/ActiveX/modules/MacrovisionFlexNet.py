# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

import logging

log = logging.getLogger("Thug")


def Initialize(self, *args): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Initialize')


def CreateJob(self, name, arg, job_id):
    log.ThugLogging.add_behavior_warn(f'[Macrovision ActiveX] CreateJob("{name}", "{arg}", "{job_id}")')
    return self


def DownloadAndExecute(self, arg0, arg1, arg2, arg3, arg4):
    log.ThugLogging.add_behavior_warn(f'[Macrovision ActiveX] DownloadAndExecute('
                                      f'"{arg0}", "{arg1}", "{arg2}", "{arg3}", "{arg4}")')

    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Macrovision ActiveX",
                                      "DownloadAndExecute",
                                      data = {
                                                "arg" : arg0,
                                                "arg1": arg1,
                                                "arg2": arg2,
                                                "arg3": arg3,
                                                "arg4": arg4
                                             },
                                      forward = False)

    if len(arg1) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Macrovision ActiveX",
                                          "DownloadAndExecute overflow",
                                          cve = "CVE-2007-2419, CVE-2007-6654")
        log.ThugLogging.Shellcode.check_shellcode(arg1)

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-2419")
    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-6654")

    log.ThugLogging.add_behavior_warn(f"[Macrovision ActiveX] Fetching from URL {arg3}")

    try:
        self._window._navigator.fetch(arg3, redirect_type = "Macrovision Exploit")
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Fetch failed')


def DownloadAndInstall(self, *args): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] DownloadAndInstall')


def AddFileEx(self, arg0, arg1, arg2, arg3, arg4, arg5, arg6): # pylint:disable=unused-argument
    if len(arg2) > 512:
        log.ThugLogging.log_exploit_event(self._window.url,
                                          "Macrovision ActiveX",
                                          "AddFileEx overflow",
                                          cve = "CVE-2007-2419")

        log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-2419")
        log.ThugLogging.Shellcode.check_shellcode(arg2)


def AddFile(self, arg0, arg1):
    log.ThugLogging.add_behavior_warn(f'[Macrovision ActiveX] AddFile("{arg0}", "{arg1}")')
    log.ThugLogging.add_behavior_warn(f"[Macrovision ActiveX] Fetching from URL {arg0}")
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Macrovision ActiveX",
                                      "AddFile/Fetch from URL",
                                      cve = "CVE-2007-2419",
                                      forward = False,
                                      data = {
                                                "url": arg0,
                                                "arg1": arg1
                                             }
                                     )

    log.ThugLogging.log_classifier("exploit", log.ThugLogging.url, "CVE-2007-2419")

    try:
        self._window._navigator.fetch(arg0, redirect_type = "Macrovision Exploit 2")
    except Exception: # pylint:disable=broad-except
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Fetch failed')


def SetPriority(self, priority): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Macrovision ActiveX] SetPriority({priority})')


def SetNotifyFlags(self, flags): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn(f'[Macrovision ActiveX] SetNotifyFlags({flags})')


def RunScheduledJobs(self): # pylint:disable=unused-argument
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] RunScheduledJobs()')
