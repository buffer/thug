# StreamAudio ChainCast VMR Client Proxy ActiveX Control 3.x
# CVE-NOMATCH

def InternalTuneIn(arg0,arg1,arg2,arg3,arg4):
	if len(arg0)>248:
		add_alert('StreamAudio ChainCast ProxyManager buffer overflow in arg0')

self.InternalTuneIn=InternalTuneIn
