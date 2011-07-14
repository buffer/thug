# Lycos FileUploader Module 2.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetHandwriterFilename(val):
    global acct

    if len(val) > 1024:
        acct.add_alert('FileUploader() overflow in HandwriterFilename property')

Attr2Fun['HandwriterFilename'] = SetHandwriterFilename
