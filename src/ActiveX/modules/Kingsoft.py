# Kingsoft Antivirus
# CVE-NOMATCH

def SetUninstallName(arg):
	if len(arg)>900:
		add_alert('Kingsoft SetUninstallName() heap overflow')

self.SetUninstallName=SetUninstallName
