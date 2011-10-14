# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

import logging
log = logging.getLogger("Thug.ActiveX")

def CreateJob(self, name, arg, job_id):
    log.warning('Macrovision ActiveX CreateObject("%s", "%s", "%s")' % (name, arg, job_id, ))
    return self

def DownloadAndExecute(self, arg0, arg1, arg2, arg3, arg4):
    if len(arg1) > 512:	
        log.warning('Macrovision ActiveX DownloadAndExecute overflow')

def AddFileEx(self, arg0, arg1, arg2, arg3, arg4, arg5, arg6):
    if len(arg2) > 512:
        log.warning('Macrovision ActiveX AddFileEx overflow')

def AddFile(self, arg0, arg1):
    log.warning('Macrovision ActiveX AddFile("%s", "%s")' % (arg0, arg1))

def SetPriority(self, priority):
    log.warning('Macrovision ActiveX SetPriority(%s)' % (priority, ))

def SetNotifyFlags(self, flags):
    log.warning('Macrovision ActiveX SetNotifyFlags(%s)' % (flags, ))

def RunScheduledJobs(self):
    log.warning('Macrovision ActiveX RunScheduledJobs()')
