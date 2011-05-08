# AOL Radio AOLMediaPlaybackControl.exe 
# CVE-2007-6250

def AppendFileToPlayList(arg):
	if len(arg) > 512: 
		add_alert('AOL AmpX overflow in AppendFileToPlayList')

self.AppendFileToPlayList = AppendFileToPlayList
