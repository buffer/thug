#  execute arbitrary code via a long argument string to the (1) src, (2) setPageMode, (3) setLayoutMode, and (4) setNamedDest methods in an AcroPDF ActiveX control
# CVE-2006-6236

acct = ActiveXAcct[self]

def Setsrc(* args):
    global acct

	acct.add_alert('AcroPDF ActiveX control is to execute arbitrary code via a long argument string to the src')

def setPageMode(* args):
    global acct

	acct.add_alert('AcroPDF ActiveX control is to execute arbitrary code via a long argument string to the setPageMode()')

def setLayoutMode(* args):
    global acct

	acct.add_alert('AcroPDF ActiveX control is to execute arbitrary code via a long argument string to the setLayoutMode()')

def setNamedDest(* args):
    global acct

	acct.add_alert('AcroPDF ActiveX control is to execute arbitrary code via a long argument string to the seNamedDest()')

def LoadFile(arg0):
    global acct

	if len(arg0) > 6000:
		acct.add_alert('AcroPDF ActiveX control is to execute arbitrary code via a long argument string to the LoadFile()')


Attr2Fun['src']    = Setsrc

self.setPageMode   = setPageMode
self.setLayoutMode = setLayoutMode
self.setNamedDest  = setNamedDest
self.LoadFile      = LoadFile
