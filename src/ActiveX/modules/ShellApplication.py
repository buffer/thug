
acct = ActiveXAcct[self]

def ShellExecute(arg1, arg2 = None, arg3 = None):
    global acct

    acct.add_alert(arg1)

self.ShellExecute = ShellExecute
self.shellexecute = ShellExecute
