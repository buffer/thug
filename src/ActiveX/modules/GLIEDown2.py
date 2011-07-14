# Ourgame GLWorld GLIEDown2.dll ActiveX Control Vulnerabilities

acct = ActiveXAcct[self]

def IEStartNative(arg0, arg1, arg2):
    global acct

    if len(arg0) > 220:
        acct.add_alert('GLWorld GLIEDown2.dll ActiveX IEStartNative Method Buffer Overflow')

self.IEStartNative = IEStartNative
