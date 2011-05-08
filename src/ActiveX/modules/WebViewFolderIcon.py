# Microsoft Internet Explorer 6 WebViewFolderIcon 
# CVE-2006-3730

def setSlice(arg0, arg1, arg2, arg3):
    if (arg0 == 0x7ffffffe):
            add_alert('WebViewFolderIcon.setSlice attack')
    add_alert(str(arg0) + " " + str(arg1) + " " + str(arg2) + " " + str(arg3))

self.setSlice = setSlice


