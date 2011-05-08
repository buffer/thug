# WinZip FileView ActiveX Control
# CVE-2006-3890,CVE-2006-5198,CVE-2006-6884

def CreateNewFolderFromName(arg):
	if len(arg)>230:
		add_alert('WinZip CreateNewFolderFromName overflow')

self.CreateNewFolderFromName=CreateNewFolderFromName
