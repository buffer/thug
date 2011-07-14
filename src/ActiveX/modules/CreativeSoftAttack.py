
acct = ActiveXAcct[self]

def Setcachefolder(val):
    global acct

    acct.add_alert('CreativeSoft ActiveX overflow in cachefolder property')

Attr2Fun['cachefolder'] = Setcachefolder
