
acct = ActiveXAcct[self]

def DownloadFile(* arg):
    global acct

	acct.add_alert('ZenturiProgramCheckerAttack attack in DownloadFile function')

def DebugMsgLog(* arg):
    global acct

	acct.add_alert('ZenturiProgramCheckerAttack attack in DebugMsgLog function')

def NavigateUrl(* arg):
    global acct

	acct.add_alert('ZenturiProgramCheckerAttack attack in NavigateUrl function')

self.DownloadFile = DownloadFile
self.DebugMsgLog  = DebugMsgLog
self.NavigateUrl  = NavigateUrl
