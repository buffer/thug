# Vantage Linguistics AnserWorks ActiveX Controls
# CVE-2007-6387

acct = ActiveXAcct[self]

def GetHistory(arg):
    global acct

    if len(arg) > 215:
        acct.add_alert('AnswerWorks overflow in GetHistory()')

def GetSeedQuery(arg):
    global acct

    if len(arg) > 215:
        acct.add_alert('AnswerWorks overflow in GetSeedQuery()')

def SetSeedQuery(arg):
    global acct

    if len(arg) > 215:
        acct.add_alert('AnswerWorks overflow in SetSeedQuery()')

self.GetHistory   = GetHistory
self.GetSeedQuery = GetSeedQuery
self.SetSeedQuery = SetSeedQuery
