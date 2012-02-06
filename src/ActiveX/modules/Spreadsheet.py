# OWC10/11.Spreadsheet ActiveX
# CVE-2009-1136

import logging
log = logging.getLogger("Thug")

def _Evaluate(self, *args):
    log.MAEC.add_behavior_warn('[OWC 10/11.Spreadsheet ActiveX] Attack in _Evaluate function',
                               'CVE-2009-1136')

def Evaluate(self, *args):
    log.MAEC.add_behavior_warn('[OWC 10/11.Spreadsheet ActiveX] Attack in Evaluate function',
                               'CVE-2009-1136')	

