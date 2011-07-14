# Microsoft VFP_OLE_Server

acct = ActiveXAcct[self]

def foxcommand(cmd):
    global acct

    acct.add_alert('Microsoft VFP_OLE_Server running ' + cmd)

self.foxcommand = foxcommand
self.FoxCommand = foxcommand
self.DoCmd      = foxcommand
self.docmd      = foxcommand
