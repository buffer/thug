
acct = ActiveXAcct[self]

def GetVariable(arg):
    global acct

    if arg == "$version":
        return "WIN 10,0,64,0"

self.GetVariable = GetVariable
