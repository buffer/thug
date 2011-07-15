# Xunlei Thunder PPLAYER.DLL_1.WORK ActiveX Control

acct = ActiveXAcct[self]

def DownURL2(arg0, arg1, arg2, arg3):
    global acct

    if len(arg0) > 1024:
        acct.add_alert('Xunlei Thunder 5.x DownURL2() overflow')

def SetFlvPlayerUrl(val):
    global acct

    if len(val) > 1060:
        acct.add_alert('Xunlei Thunder XPPlayer Class \"FlvPlayerUrl\" Property Handling Buffer Overflow')

def SetLogo(val):
    global acct

    if len(val) > 128:
        acct.add_alert('PPStream (PowerPlayer.dll 2.0.1.3829) ActiveX Remote Overflow Exploit in Logo property')

self.DownURL2            = DownURL2
Attr2Fun['FlvPlayerUrl'] = SetFlvPlayerUrl
Attr2Fun['Logo']         = SetLogo
