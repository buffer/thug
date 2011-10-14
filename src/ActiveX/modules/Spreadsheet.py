# OWC10/11.Spreadsheet ActiveX
# CVE-2009-1136

import logging
log = logging.getLogger("Thug.ActiveX")

def _Evaluate(self, *args):
    log.warning('OWC 10/11.Spreadsheet ActiveX attack in _Evaluate function')

def Evaluate(self, *args):
    log.warning('OWC 10/11.Spreadsheet ActiveX attack in Evaluate function')	

