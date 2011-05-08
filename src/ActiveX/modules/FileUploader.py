# Lycos FileUploader Module 2.x
# CVE-NOMATCH

def SetHandwriterFilename(val):
	if len(val)>1024:
		add_alert('FileUploader() overflow in HandwriterFilename property')


Attr2Fun['HandwriterFilename']=SetHandwriterFilename
