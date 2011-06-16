# NamoInstaller ActiveX Control 1.x - 3.x
# CVE-NOMATCH

def Install(arg):
    if str([arg]).find('http') > -1:
        add_alert('Insecure download via NamoInstaller of ' + arg)
    if len(arg) > 1024:
        add_alert('NamoInstaller overflow in Install')

self.Install = Install
