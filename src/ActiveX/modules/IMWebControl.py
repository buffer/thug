# iMesh<= 7.1.0.x IMWebControl Class
# CVE-2007-6493, CVE-2007-6492

acct = ActiveXAcct[self]

def ProcessRequestEx(arg):
    global acct

    if len(arg) == 0:
        acct.add_alert('IMWebControl NULL value in ProcessRequestEx()')

def SetHandler(arg):
    global acct

    if str([arg]) == '218959117':
        acct.add_alert('IMWebControl overflow in SetHandler()')

self.ProcessRequestEx = ProcessRequestEx
self.SetHandler       = SetHandler
