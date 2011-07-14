# NamoInstaller ActiveX Control 1.x - 3.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def Install(arg):
    global acct

    if str([arg]).find('http') > -1:
        acct.add_alert('Insecure download via NamoInstaller of ' + arg)
    if len(arg) > 1024:
        acct.add_alert('NamoInstaller overflow in Install')

self.Install = Install
