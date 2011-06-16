# MPS.StormPlayer.1  'advanceOpen' 
# CVE

def advancedOpen(arg0, arg1):
    if len(arg0) > 259:
	    add_alert('MPS.StormPlayer.1 ActiveX advanceOpen Method Overflow')

def isDVDPath(arg0):
	if len(arg0)>246:
		add_alert('MPS.StormPlayer.1 ActiveX isDVDPath Method Overflow')

def rawParse(arg0):
	if len(arg0)>259:
		add_alert('MPS.StormPlayer.1 ActiveX rawParse Method Overflow')

def OnBeforeVideoDownload(arg0):
	if len(arg0)>4124:
		add_alert('MPS.StromPlayer.1 ActiveX OnBeforeVideoDownload Method Overflow')

def SetURL(val):
    if len(val)>259:
		add_alert('MPS.StormPlayer.1 ActiveX URL Console Overflow')

def SetbackImage(val):
	if len(val)>292:
		add_alert('MPS.StormPlayer.1 ActiveX backImage Console Overflow')

def SettitleImage(val):
	if len(val)>296:
		add_alert('MPS.StromPlayer.1 ActiveX titleImage Console Overflow')

self.advancedOpen = advancedOpen
self.isDVDPath = isDVDPath
self.rawParse=rawParse
self.OnBeforeVideoDownload=OnBeforeVideoDownload

Attr2Fun['URL'] = SetURL
Attr2Fun['backImage'] = SetbackImage
Attr2Fun['titleImage'] = SettitleImage


