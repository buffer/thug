# Vantage Linguistics AnserWorks ActiveX Controls
# CVE-2007-6387

import logging
log = logging.getLogger("Thug.ActiveX")

def GetHistory(self, arg):
    if len(arg) > 215:
        log.warning('AnswerWorks overflow in GetHistory')

def GetSeedQuery(self, arg):
    if len(arg) > 215:
        log.warning('AnswerWorks overflow in GetSeedQuery')

def SetSeedQuery(self, arg):
    if len(arg) > 215:
        log.warning('AnswerWorks overflow in SetSeedQuery')
