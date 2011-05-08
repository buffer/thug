# RTSP MPEG4 SP Control 1.x
# CVE-NOMATCH

def SetMP4Prefix(val):
	if len(val)>128:
		add_alert('RTSP MPEG4 SP Control overflow in MP4Prefix property')

Attr2Fun['MP4Prefix']=SetMP4Prefix
