# Facebook Photo Uploader 4.x
# CVE-NOMATCH

def SetExtractIptc(val):
	if len(val)>255:
		add_alert('FaceBook PhotoUploader overflow in ExtractIptc property')

def SetExtractExif(val):
	if len(val)>255:
		add_alert('FaceBook PhotoUploader overflow in ExtractExif property')

Attr2Fun['ExtractIptc']=SetExtractIptc
Attr2Fun['ExtractExif']=SetExtractExif
