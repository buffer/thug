# BaoFeng Storm ActiveX Control SetAttributeValue() Buffer Overflow Vulnerability
# CVE-2009-1807

def SetAttributeValue(arg0,arg1,arg2):
	if len(arg0)>260:
		add_alert('Storm ActiveX Control SetAttributeValue() Buffer Overflow')

self.SetAttributeValue=SetAttributeValue
