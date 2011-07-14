

acct = ActiveXAcct[self]

def Open():
    global acct
    
    acct.add_alert("Adodb.Stream Open")

def Write(s):
    global acct
    
    acct.add_alert("Adodb.Stream Write")
    acct.add_alert(s)

def SaveToFile(filename, opt):
    global acct

    acct.add_alert("Adodb.Stream SaveToFile")
    acct.add_alert(filename)
    acct.add_alert(opt)

def Close():
    global acct

    acct.add_alert("Adodb.Stream Close")


self.Open	    = Open
self.Write	    = Write
self.SaveToFile = SaveToFile
self.Close	    = Close
