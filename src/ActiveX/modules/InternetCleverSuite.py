# Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX) Arbitrary file download/overwrite Exploit

def GetToFile(url, file):
    add_alert('Clever Internet ActiveX Suite 6.2 (CLINETSUITEX6.OCX) Arbitrary File Download/Overwrite Exploit')
    add_alert('URL : %s' % (url, ))
    add_alert('File: %s' % (file, ))

self.GetToFile = GetToFile
