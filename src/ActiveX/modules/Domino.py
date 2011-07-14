# IBM Lotus Domino Web Access Control ActiveX Control
# CVE-2007-4474

acct = ActiveXAcct[self]

def SetGeneral_ServerName(val):
    global acct

    if len(val) > 1024:
        acct.add_alert('Domino overflow with General_ServerName property')

def SetGeneral_JunctionName(val):
    global acct

    if len(val) > 1024:
        acct.add_alert('Domino overflow with General_JunctionName property')

def SetMail_MailDbPath(val):
    global acct

    if len(val) > 1024:
        acct.add_alert('Domino overflow with Mail_MailDbPath property')

Attr2Fun['General_ServerName']   = SetGeneral_ServerName
Attr2Fun['General_JunctionName'] = SetGeneral_JunctionName
Attr2Fun['Mail_MailDbPath']      = SetMail_MailDbPath
