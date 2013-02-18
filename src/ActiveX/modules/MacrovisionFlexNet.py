# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

import logging
log = logging.getLogger("Thug")

def Initialize(self, *args):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Initialize')

def CreateJob(self, name, arg, job_id):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] CreateObject("%s", "%s", "%s")' % (name, arg, job_id, ))
    return self

def DownloadAndExecute(self, arg0, arg1, arg2, arg3, arg4):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] DownloadAndExecute("%s", "%s", "%s", "%s", "%s")' % (arg0, arg1, arg2, arg3, arg4))

    if len(arg1) > 512:	
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] DownloadAndExecute overflow', 'CVE-2007-2419, CVE-2007-6654')

    log.ThugLogging.add_behavior_warn("[Macrovision ActiveX] Fetching from URL %s" % (arg3, ))

    try:
        response, content = self._window._navigator.fetch(arg3, redirect_type = "Macrovision Exploit")
    except:
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Fetch failed')

def DownloadAndInstall(self, *args):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] DownloadAndInstall')

def AddFileEx(self, arg0, arg1, arg2, arg3, arg4, arg5, arg6):
    if len(arg2) > 512:
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] AddFileEx overflow', 'CVE-2007-2419')

def AddFile(self, arg0, arg1):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] AddFile("%s", "%s")' % (arg0, arg1))
    log.ThugLogging.add_behavior_warn("[Macrovision ActiveX] Fetching from URL %s" % (arg0, ))

    try:
        response, content = self._window._navigator.fetch(arg0, redirect_type = "Macrovision Exploit 2")
    except:
        log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] Fetch failed')

def SetPriority(self, priority):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] SetPriority(%s)' % (priority, ))

def SetNotifyFlags(self, flags):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] SetNotifyFlags(%s)' % (flags, ))

def RunScheduledJobs(self):
    log.ThugLogging.add_behavior_warn('[Macrovision ActiveX] RunScheduledJobs()')
