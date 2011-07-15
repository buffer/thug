# MPS.StormPlayer.1  'advanceOpen' 
# CVE

acct = ActiveXAcct[self]

def advancedOpen(arg0, arg1):
    global acct
    
    if len(arg0) > 259:
        acct.add_alert('MPS.StormPlayer.1 ActiveX advanceOpen Method Overflow')

def isDVDPath(arg0):
    global acct

    if len(arg0) > 246:
        acct.add_alert('MPS.StormPlayer.1 ActiveX isDVDPath Method Overflow')

def rawParse(arg0):
    global acct

    if len(arg0) > 259:
        acct.add_alert('MPS.StormPlayer.1 ActiveX rawParse Method Overflow')

def OnBeforeVideoDownload(arg0):
    global acct

    if len(arg0) > 4124:
        acct.add_alert('MPS.StromPlayer.1 ActiveX OnBeforeVideoDownload Method Overflow')

def SetURL(val):
    global acct

    if len(val) > 259:
        acct.add_alert('MPS.StormPlayer.1 ActiveX URL Console Overflow')

def SetbackImage(val):
    global acct

    if len(val) > 292:
        acct.add_alert('MPS.StormPlayer.1 ActiveX backImage Console Overflow')

def SettitleImage(val):
    global acct

    if len(val) > 296:
        acct.add_alert('MPS.StromPlayer.1 ActiveX titleImage Console Overflow')

self.advancedOpen          = advancedOpen
self.isDVDPath             = isDVDPath
self.rawParse              = rawParse
self.OnBeforeVideoDownload = OnBeforeVideoDownload

Attr2Fun['URL']            = SetURL
Attr2Fun['backImage']      = SetbackImage
Attr2Fun['titleImage']     = SettitleImage


