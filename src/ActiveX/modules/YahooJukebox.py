# Yahoo! Music Jukebox 2.x
# CVE-NOMATCH

def AddBitmap(arg0,arg1,arg2,arg3,arg4,arg5):
	if len(arg1)>256:
		add_alert('Yahoo Jukebox overflow in AddBitmap()')

def AddButton(arg0,arg1):
	if len(arg0)>256:
		add_alert('Yahoo Jukebox overflow in AddButton()')

def AddImage(arg0,arg1):
	if len(arg0)>256:
		add_alert('Yahoo Jukebox overflow in AddImage()')

self.AddBitmap=AddBitmap
self.AddButton=AddButton
self.AddImage=AddImage
