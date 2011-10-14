# Microsoft Internet Explorer 6 WebViewFolderIcon 
# CVE-2006-3730

import logging 
log = logging.getLogger("Thug.ActiveX")

def setSlice(self, arg0, arg1, arg2, arg3):
    log.warning('WebViewFolderIcon ActiveX setSlice(%s, %s, %s, %s)' % (arg0, arg1, arg2, arg3, ))
    if arg0 == 0x7ffffffe:
        log.warning('WebViewFolderIcon ActiveX setSlice attack')

