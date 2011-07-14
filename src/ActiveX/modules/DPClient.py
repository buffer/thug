# Xunlei DPClient.Vod.1 ActiveX Control DownURL2 Method Remote Buffer Overflow Vulnerability
# CVE-2007-5064

acct = ActiveXAcct[self]

def DownURL2(arg0, *args):
    global acct

    if len(arg0) > 1024:
        acct.add_alert('DPClient.Vod.1 ActiveX Control DownURL2 Method Buffer Overflow')

self.DownURL2 = DownURL2

