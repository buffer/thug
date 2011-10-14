# IBM Lotus Domino Web Access Control ActiveX Control
# CVE-2007-4474

import logging
log = logging.getLogger("Thug.ActiveX")

def SetGeneral_ServerName(self, val):
    self.__dict__['General_ServerName'] = val

    if len(val) > 1024:
        log.warning('Domino overflow in General_ServerName property')

def SetGeneral_JunctionName(self, val):
    self.__dict__['General_JunctionName'] = val

    if len(val) > 1024:
        log.warning('Domino overflow in General_JunctionName property')

def SetMail_MailDbPath(self, val):
    self.__dict__['Mail_MailDbPath'] = val

    if len(val) > 1024:
        log.warning('Domino overflow in Mail_MailDbPath property')

def InstallBrowserHelperDll(self):
    pass

