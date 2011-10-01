
acct = ActiveXAcct[self]

def GetVariable(arg):
    global acct

    if arg == "$version":
        return "WIN 9,0,64,0"

self.GetVariable = GetVariable
