# AOL Radio AOLMediaPlaybackControl.exe 
# CVE-2007-6250

import logging
log = logging.getLogger("Thug.ActiveX")

def AppendFileToPlayList(self, arg):
    if len(arg) > 512: 
        log.warning('AOL AmpX overflow in AppendFileToPlayList')

def ConvertFile(self, *arg):
    #FIXME
    if len(arg[0]) > 512:
        log.warning('AOL AmpX overflow in ConvertFile')

