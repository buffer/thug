# MacrovisionJob, MacrovisionFlexNet
# CVE-2007-2419, CVE-2007-5660, CVE-2007-6654, CVE-2007-0321, CVE-2007-0328

object = self

def CreateJob(name, arg, job_id):
    global object
    return object

def DownloadAndExecute(arg0, arg1, arg2, arg3, arg4):
	if len(arg1) > 512:	
		add_alert('Macrovision ActiveX DownloadAndExecute overflow')

def AddFileEx(arg0, arg1, arg2, arg3, arg4, arg5, arg6):
	if len(arg2) > 512:
		add_alert('Macrovision ActiveX AddFileEx overflow')

def AddFile(arg0, arg1):
    add_alert('Macrovision ActiveX AddFile Arguments')
    add_alert("%s ---> %s" % (arg0, arg1))

def SetPriority(priority):
    return

def SetNotifyFlags(flags):
    return

def RunScheduledJobs():
    return

self.CreateJob          = CreateJob
self.DownloadAndExecute = DownloadAndExecute
self.AddFileEx          = AddFileEx
self.AddFile            = AddFile
self.SetPriority        = SetPriority
self.SetNotifyFlags     = SetNotifyFlags
self.RunScheduledJobs   = RunScheduledJobs
