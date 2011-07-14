# Univeral HTTP File Upload (UUploaderSverD.dll - v6.0.0.35)
# CVE-NOMATCH

acct = ActiveXAcct[self]

def RemoveFileOrDir(arg0, arg1):
    global acct

	acct.add_alert('UniversalUpload deleted ' + arg0)

self.RemoveFileOrDir = RemoveFileOrDir
