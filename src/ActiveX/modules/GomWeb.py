# GOM Player GOM Manager ActiveX Control
# CVE-2007-5779

acct = ActiveXAcct[self]

def OpenURL(arg):
    global acct

    if len(arg) > 500:
        acct.add_alert('GOM Player 2 overflow in OpenURL()')

self.OpenURL = OpenURL
