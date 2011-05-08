# D-Link MPEG4 SHM Audio Control
# CVE-NOMATCH

def SetUrl(val):
	if len(val)>1024:
		add_alert('DLinkMPEG overflow in Url property')

Attr2Fun['Url']=SetUrl
