# MySpace Uploader Control 1.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetAction(val):
    global acct

    if len(val) > 512:
        acct.add_alert('Myspace UPloader overflow with Action property')

Attr2Fun['Action'] = SetAction
