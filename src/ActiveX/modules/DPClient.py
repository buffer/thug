# Xunlei DPClient.Vod.1 ActiveX Control DownURL2 Method Remote Buffer Overflow Vulnerability
# CVE-2007-5064

def DownURL2(arg0,*args):
	if len(arg0)>1024:
		add_alert('DPClient.Vod.1 ActiveX Control DownURL2 Method  Buffer Overflow')

self.DownURL2=DownURL2

