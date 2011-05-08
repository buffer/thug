# Persists Software XUpload control, version 2.1.0.1.
# CVE-2007-6530

def AddFolder(arg):
    if len(arg) > 1024:
        add_alert('XUpload overflow in AddFolder()')

def AddFile(arg):
    if len(arg) > 255: 
        add_alert('XUpload overflow in AddFile()')

self.AddFolder = AddFolder
self.AddFile = AddFile
