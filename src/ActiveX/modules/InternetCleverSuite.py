# Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX) Arbitrary file download/overwrite Exploit

acct = ActiveXAcct[self]

def GetToFile(url, file):
    global acct

    acct.add_alert('Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX) Arbitrary File Download/Overwrite Exploit')
    acct.add_alert('URL : %s' % (url, ))
    acct.add_alert('File: %s' % (file, ))

self.GetToFile = GetToFile
