# Yahoo! Music Jukebox 2.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def AddBitmap(arg0, arg1, arg2, arg3, arg4, arg5):
    global acct

    if len(arg1) > 256:
        acct.add_alert('Yahoo Jukebox overflow in AddBitmap()')

def AddButton(arg0, arg1):
    global acct

    if len(arg0) > 256:
        acct.add_alert('Yahoo Jukebox overflow in AddButton()')

def AddImage(arg0, arg1):
    global acct

    if len(arg0) > 256:
        acct.add_alert('Yahoo Jukebox overflow in AddImage()')

self.AddBitmap = AddBitmap
self.AddButton = AddButton
self.AddImage  = AddImage
