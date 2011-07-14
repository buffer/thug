# Comodo AntiVirus 2.0
# CVE-NOMATCH

acct = ActiveXAcct[self]

def ExecuteStr(cmd, args):
    global acct

    acct.add_alert('Comodo will execute: ' + cmd + ' ' + args)

self.ExecuteStr = ExecuteStr
