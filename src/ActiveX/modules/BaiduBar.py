# BaiduBar.dll ActiveX DloadDS() Remote Code Execution Vulnerability
# BUGTRAQ  ID: 25121

def DloadDS(arg0, arg1, arg2):
	if str(arg0).lower().find(".cab") != -1:
		add_alert('BaiduBar.dll ActiveX DloadDS() function is trying to download %s' % (arg0, ))

self.DloadDS = DloadDS
