
acct = ActiveXAcct[self]

def SetWksPictureInterface(val):
    global acct

    acct.add_alert('MicrosoftWorks7 ActiveX overflow in WksPictureInterface property')

Attr2Fun['WksPictureInterface'] = SetWksPictureInterface
