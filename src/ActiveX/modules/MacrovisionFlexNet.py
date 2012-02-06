# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

import os
import hashlib
import logging
log = logging.getLogger("Thug")

def Initialize(self, *args):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] Initialize')

def CreateJob(self, name, arg, job_id):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] CreateObject("%s", "%s", "%s")' % (name, arg, job_id, ))
    return self

def DownloadAndExecute(self, arg0, arg1, arg2, arg3, arg4):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] DownloadAndExecute("%s", "%s", "%s", "%s", "%s")' % (arg0, arg1, arg2, arg3, arg4))

    if len(arg1) > 512:	
        log.MAEC.add_behavior_warn('[Macrovision ActiveX] DownloadAndExecute overflow',
                                   'CVE-2007-2419, CVE-2007-6654')

    log.MAEC.add_behavior_warn("[Macrovision ActiveX] Fetching from URL %s" % (arg3, ))

    try:
        response, content = self._window._navigator.fetch(arg3)
    except:
        log.MAEC.add_behavior_warn('[Macrovision  ActiveX] Fetch failed')
        return

    if not response or response.status == 404:
        log.MAEC.add_behavior_warn("[Macrovision ActiveX] FileNotFoundError: %s" % (arg3, ))
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.MAEC.add_behavior_warn("[Macrovision ActiveX] Saving File: " + filename)
  
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def DownloadAndInstall(self, *args):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] DownloadAndInstall')

def AddFileEx(self, arg0, arg1, arg2, arg3, arg4, arg5, arg6):
    if len(arg2) > 512:
        log.MAEC.add_behavior_warn('[Macrovision ActiveX] AddFileEx overflow',
                                   'CVE-2007-2419')

def AddFile(self, arg0, arg1):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] AddFile("%s", "%s")' % (arg0, arg1))
    log.MAEC.add_behavior_warn("[Macrovision ActiveX] Fetching from URL %s" % (arg0, ))

    try:
        response, content = self._window._navigator.fetch(arg0)
    except:
        log.MAEC.add_behavior_warn('[Macrovision  ActiveX] Fetch failed')
        return

    if not response or response.status == 404:
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.MAEC.add_behavior_warn("[Macrovision ActiveX] Saving File: " + filename)
  
    baseDir = log.baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def SetPriority(self, priority):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] SetPriority(%s)' % (priority, ))

def SetNotifyFlags(self, flags):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] SetNotifyFlags(%s)' % (flags, ))

def RunScheduledJobs(self):
    log.MAEC.add_behavior_warn('[Macrovision ActiveX] RunScheduledJobs()')
