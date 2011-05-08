# Vantage Linguistics AnserWorks ActiveX Controls
# CVE-2007-6387

def GetHistory(arg):
	if len(arg)>215:
		add_alert('AnswerWorks overflow in GetHistory()')

def GetSeedQuery(arg):
	if len(arg)>215:
		add_alert('AnswerWorks overflow in GetSeedQuery()')

def SetSeedQuery(arg):
	if len(arg)>215:
		add_alert('AnswerWorks overflow in SetSeedQuery()')

self.GetHistory=GetHistory
self.GetSeedQuery=GetSeedQuery
self.SetSeedQuery=SetSeedQuery
