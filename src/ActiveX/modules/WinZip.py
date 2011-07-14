# WinZip FileView ActiveX Control
# CVE-2006-3890,CVE-2006-5198,CVE-2006-6884

acct = ActiveXAcct[self]

def CreateNewFolderFromName(arg):
    global acct

	if len(arg) > 230:
		acct.add_alert('WinZip CreateNewFolderFromName overflow')

self.CreateNewFolderFromName = CreateNewFolderFromName
