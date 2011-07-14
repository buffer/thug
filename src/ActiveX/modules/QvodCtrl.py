# Qvod Player QvodCtrl Class ActiveX Control
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetURL(val):
    global acct

	if len(val) > 800:
		acct.add_alert('Qvod Player QvodCtrl Class ActiveX Control overflow in URL property')

Attr2Fun['URL'] = SetURL
Attr2Fun['url'] = SetURL
