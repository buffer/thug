# SSReader Pdg2 ActiveX control (pdg2.dll)
# CVE-2007-5892

def Register(arg0, arg1):
    if len(arg1) > 255: 
        add_alert('SSReader Pdg2 ActiveX Register Method Overflow')

def LoadPage(arg0,arg1,arg2,arg3):
    if(len(arg0)>255):
        add_alert('SSReader Pdg2 ActiveX LoadPage Method Overflow')

self.Register = Register
self.LoadPage = LoadPage
