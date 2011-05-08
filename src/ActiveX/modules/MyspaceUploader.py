# MySpace Uploader Control 1.x
# CVE-NOMATCH

def SetAction(val):
	if len(val)>512:
		add_alert('Myspace UPloader overflow with Action property')


Attr2Fun['Action']=SetAction
