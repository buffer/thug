# SSReader Pdg2 ActiveX control (pdg2.dll)
# CVE-2007-5892

acct = ActiveXAcct[self]

def Register(arg0, arg1):
    global acct

    if len(arg1) > 255:
        acct.add_alert('SSReader Pdg2 ActiveX Register Method Overflow')

def LoadPage(arg0,arg1,arg2,arg3):
    global acct

    if(len(arg0)>255):
        acct.add_alert('SSReader Pdg2 ActiveX LoadPage Method Overflow')

self.Register = Register
self.LoadPage = LoadPage
