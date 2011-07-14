# D-Link MPEG4 SHM Audio Control
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetUrl(val):
    global acct

    if len(val) > 1024:
        acct.add_alert('DLinkMPEG overflow in Url property')

Attr2Fun['Url'] = SetUrl
