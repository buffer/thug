def DownloadFile(* arg):
	add_alert('ZenturiProgramCheckerAttack attack in \'DownloadFile\' function')

def DebugMsgLog(* arg):
	add_alert('ZenturiProgramCheckerAttack attack in \'DebugMsgLog\' function')

def NavigateUrl(* arg):
	add_alert('ZenturiProgramCheckerAttack attack in \'NavigateUrl\' function')

self.DownloadFile=DownloadFile
self.DebugMsgLog=DebugMsgLog
self.NavigateUrl=NavigateUrl
