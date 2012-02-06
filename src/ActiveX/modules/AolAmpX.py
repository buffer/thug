# AOL Radio AOLMediaPlaybackControl.exe 
# CVE-2007-6250

import logging
log = logging.getLogger("Thug")

def AppendFileToPlayList(self, arg):
    if len(arg) > 512: 
        log.MAEC.add_behavior_warn('[AOL Radio AOLMediaPlaybackControl ActiveX] Overflow in AppendFileToPlayList', 
                                   'CVE-2007-6250')

def ConvertFile(self, *arg):
    #FIXME
    if len(arg[0]) > 512:
        log.MAEC.add_behavior_warn('[AOL Radio AOLMediaPlaybackControl ActiveX] Overflow in ConvertFile', 
                                   'CVE-2007-6250')

