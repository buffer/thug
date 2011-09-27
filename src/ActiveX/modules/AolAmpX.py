# AOL Radio AOLMediaPlaybackControl.exe 
# CVE-2007-6250

acct   = ActiveXAcct[self]

def AppendFileToPlayList(arg):
    global acct

    if len(arg) > 512: 
        acct.add_alert('AOL AmpX overflow in AppendFileToPlayList')

def ConvertFile(*arg):
    global acct

    #FIXME
    if len(arg[0]) > 512:
        acct.add_alert('AOL AmpX overflow in ConvertFile')

self.AppendFileToPlayList = AppendFileToPlayList
self.ConvertFile          = ConvertFile
