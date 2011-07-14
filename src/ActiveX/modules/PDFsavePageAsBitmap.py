# eXPert PDF ViewerX ActiveX Control "savePageAsBitmap()" Insecure Method
# CVE-2008-4919

acct = ActiveXAcct[self]

def savePageAsBitmap(arg0):
    global acct

	acct.add_alert('Overwrite arbitrary files via a full pathname:' + arg0 + ' in the savePageAsBitmap method')

self.savePageAsBitmap = savePageAsBitmap
