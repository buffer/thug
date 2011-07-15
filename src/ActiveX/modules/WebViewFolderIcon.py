# Microsoft Internet Explorer 6 WebViewFolderIcon 
# CVE-2006-3730

acct = ActiveXAcct[self]

def setSlice(arg0, arg1, arg2, arg3):
    global acct

    if arg0 == 0x7ffffffe:
        acct.add_alert('WebViewFolderIcon.setSlice attack')
    acct.add_alert(str(arg0) + " " + str(arg1) + " " + str(arg2) + " " + str(arg3))

self.setSlice = setSlice


