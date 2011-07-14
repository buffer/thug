# Kingsoft Antivirus
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetUninstallName(arg):
    global acct

    if len(arg) > 900:
        acct.add_alert('Kingsoft SetUninstallName() heap overflow')

self.SetUninstallName = SetUninstallName
