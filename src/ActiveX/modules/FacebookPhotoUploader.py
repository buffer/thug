# Facebook Photo Uploader 4.x
# CVE-NOMATCH

acct = ActiveXAcct[self]

def SetExtractIptc(val):
    global acct

    if len(val) > 255:
        acct.add_alert('FaceBook PhotoUploader overflow in ExtractIptc property')

def SetExtractExif(val):
    global acct

    if len(val) > 255:
        acct.add_alert('FaceBook PhotoUploader overflow in ExtractExif property')

Attr2Fun['ExtractIptc'] = SetExtractIptc
Attr2Fun['ExtractExif'] = SetExtractExif
