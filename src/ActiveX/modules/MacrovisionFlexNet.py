# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

import os
import hashlib
import logging
log = logging.getLogger("Thug.ActiveX")

def Initialize(self, *args):
    log.warning('Macrovision ActiveX Initialize')

def CreateJob(self, name, arg, job_id):
    log.warning('Macrovision ActiveX CreateObject("%s", "%s", "%s")' % (name, arg, job_id, ))
    return self

def DownloadAndExecute(self, arg0, arg1, arg2, arg3, arg4):
    log.warning('[Macrovision ActiveX] DownloadAndExecute("%s", "%s", "%s", "%s", "%s")' % (arg0, arg1, arg2, arg3, arg4))

    if len(arg1) > 512:	
        log.warning('Macrovision ActiveX DownloadAndExecute overflow')

    log.warning("[Macrovision ActiveX] Fetching from URL %s" % (arg3, ))

    try:
        response, content = self._window._navigator.fetch(arg3)
    except:
        log.warning('[Macrovision  ActiveX] Fetch failed')
        return

    if not response or response.status == 404:
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.warning("[Macrovision ActiveX] Saving File: " + filename)
  
    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def DownloadAndInstall(self, *args):
    log.warning('Macrovision ActiveX DownloadAndInstall')

def AddFileEx(self, arg0, arg1, arg2, arg3, arg4, arg5, arg6):
    if len(arg2) > 512:
        log.warning('Macrovision ActiveX AddFileEx overflow')

def AddFile(self, arg0, arg1):
    log.warning('[Macrovision ActiveX] AddFile("%s", "%s")' % (arg0, arg1))
    log.warning("[Macrovision ActiveX] Fetching from URL %s" % (arg0, ))

    try:
        response, content = self._window._navigator.fetch(arg0)
    except:
        log.warning('[Macrovision  ActiveX] Fetch failed')
        return

    if not response or response.status == 404:
        return 

    md5 = hashlib.md5()
    md5.update(content)
    filename = md5.hexdigest()

    log.warning("[Macrovision ActiveX] Saving File: " + filename)
  
    baseDir = logging.getLogger("Thug").baseDir

    try:
        fd = os.open(os.path.join(baseDir, filename), os.O_RDWR | os.O_CREAT)
        os.write(fd, content)
        os.close(fd)
    except:
        pass

def SetPriority(self, priority):
    log.warning('Macrovision ActiveX SetPriority(%s)' % (priority, ))

def SetNotifyFlags(self, flags):
    log.warning('Macrovision ActiveX SetNotifyFlags(%s)' % (flags, ))

def RunScheduledJobs(self):
    log.warning('Macrovision ActiveX RunScheduledJobs()')
