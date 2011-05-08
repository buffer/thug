# Qvod Player QvodCtrl Class ActiveX Control
# CVE-NOMATCH

def SetURL(val):
	if len(val)>800:
		add_alert('Qvod Player QvodCtrl Class ActiveX Control overflow in URL property')

Attr2Fun['URL']=SetURL
Attr2Fun['url']=SetURL
