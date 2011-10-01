
acct = ActiveXAcct[self]

def GetVariable(arg):
    global acct

    if arg == "$version":
        acct.add_alert("GetVariable($version)")
        return "WIN 10,0,64,0"

self.GetVariable = GetVariable
