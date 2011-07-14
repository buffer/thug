# DivX Player 6.6.0 ActiveX Control
# CVE-NOMATCHd

acct = ActiveXAcct[self]

def SetPassword(arg0):
    global acct

    if len(arg0) > 128:
        acct.add_alert('DivX overflow in SetPassword()');

self.SetPassword = SetPassword
