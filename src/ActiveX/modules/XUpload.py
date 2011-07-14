# Persists Software XUpload control, version 2.1.0.1.
# CVE-2007-6530

acct = ActiveXAcct[self]

def AddFolder(arg):
    global acct

    if len(arg) > 1024:
        acct.add_alert('XUpload overflow in AddFolder()')

def AddFile(arg):
    global acct

    if len(arg) > 255: 
        acct.add_alert('XUpload overflow in AddFile()')

self.AddFolder = AddFolder
self.AddFile   = AddFile
