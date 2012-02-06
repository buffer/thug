# Vantage Linguistics AnserWorks ActiveX Controls
# CVE-2007-6387

import logging
log = logging.getLogger("Thug")

def GetHistory(self, arg):
    if len(arg) > 215:
        log.MAEC.add_behavior_warn('[AnswerWorks ActiveX] Overflow in GetHistory', 'CVE-2007-6387')

def GetSeedQuery(self, arg):
    if len(arg) > 215:
        log.MAEC.add_behavior_warn('[AnswerWorks ActiveX] Overflow in GetSeedQuery', 'CVE-2007-6387')

def SetSeedQuery(self, arg):
    if len(arg) > 215:
        log.MAEC.add_behavior_warn('[AnswerWorks ActiveX] Overflow in SetSeedQuery', 'CVE-2007-6387')
