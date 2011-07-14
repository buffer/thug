# BaoFeng Storm ActiveX Control SetAttributeValue() Buffer Overflow Vulnerability
# CVE-2009-1807

acct = ActiveXAcct[self]

def SetAttributeValue(arg0, arg1, arg2):
    global acct

	if len(arg0) > 260:
		acct.add_alert('Storm ActiveX Control SetAttributeValue() Buffer Overflow')

self.SetAttributeValue = SetAttributeValue
