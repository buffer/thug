# AOL Radio AOLMediaPlaybackControl.exe 
# CVE-2007-6250

acct = ActiveXAcct[self]

def AppendFileToPlayList(arg):
    global acct

    if len(arg) > 512: 
        acct.add_alert('AOL AmpX overflow in AppendFileToPlayList')

self.AppendFileToPlayList = AppendFileToPlayList
