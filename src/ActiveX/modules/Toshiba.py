# Toshiba Surveillance (Surveillix) RecordSend Class (MeIpCamX.DLL 1.0.0.4)
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetPort(arg):
    global acct

    if len(arg) > 10:
        acct.add_alert('Toshiba Surveillance overflow in SetPort()')

def SetIpAddress(arg):
    global acct

    if len(arg) > 18:
        acct.add_alert('Toshiba Surveillance overflow in SetIpAddress()')

self.SetPort      = SetPort
self.SetIpAddress = SetIpAddress
