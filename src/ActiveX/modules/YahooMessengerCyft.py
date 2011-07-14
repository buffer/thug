# Yahoo! Messenger 8.x CYTF ActiveX Control

acct = ActiveXAcct[self]

def GetFile(url, local, arg2, arg3, cmd):
    global acct

	acct.add_alert('Yahoo! Messenger 8.x CYTF download of ' + url)

self.GetFile = GetFile
