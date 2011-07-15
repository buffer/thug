
acct = ActiveXAcct[self]

def Seturl(val):
    global acct

    acct.add_alert('RediffBolDownloader ActiveX overflow in url property')

Attr2Fun['url'] = Seturl
