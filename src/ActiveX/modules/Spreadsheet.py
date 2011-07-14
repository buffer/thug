# OWC10/11.Spreadsheet ActiveX
# CVE-2009-1136

acct = ActiveXAcct[self]

def _Evaluate(*args):
    global acct

    acct.add_alert('OWC 10/11.Spreadsheet ActiveX attack in _Evaluate function')

def Evaluate(*args):
    global acct

    acct.add_alert('OWC 10/11.Spreadsheet ActiveX attack in Evaluate function')	

self._Evaluate = _Evaluate
self.Evaluate  = Evaluate


